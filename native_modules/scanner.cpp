/*
 * TRAIN Framework - native_modules/scanner.cpp
 * -----------------------------------------------
 * Multi-threaded TCP port scanner with simple banner grabbing.
 *
 * Goal: scan a port range on a given target (IP/hostname), grab a simple
 * banner (first response) from open ports, and print the result as JSON
 * to stdout - the Python TUI (via core/bridge.py) will call this as a
 * subprocess and parse the JSON.
 *
 * Design notes:
 *  - Instead of spawning one thread per port, a fixed-size thread pool of
 *    workers pulls ports from a shared work queue (avoids wasting resources).
 *  - Timeouts are handled with select() so closed/filtered ports never hang
 *    the program for long.
 *  - This ONLY connects and reads whatever the service sends back; it never
 *    sends any exploit/attack payload.
 *
 * Manual compilation:
 *   g++ -std=c++17 -O2 -pthread scanner.cpp -o train_scanner
 *
 * Usage:
 *   ./train_scanner <target> <start_port> <end_port> [thread_count] [timeout_ms]
 *   ./train_scanner 192.168.10.50 1 1024 100 500
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace train {

struct ScanResult {
    int port;
    bool open;
    std::string service_guess;
    std::string banner;
};

// Best-effort service name guess for common ports (a small subset of
// nmap's nmap-services file - not exhaustive, just a quick hint).
std::string guess_service(int port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 111: return "rpcbind";
        case 135: return "msrpc";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "microsoft-ds";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 6379: return "redis";
        case 8080: return "http-proxy";
        default: return "unknown";
    }
}

// Simple JSON string escaping (enough for special characters in banners).
std::string json_escape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out << buf;
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

class PortScanner {
public:
    PortScanner(std::string target, int start_port, int end_port,
                int thread_count, int timeout_ms)
        : target_(std::move(target)),
          start_port_(start_port),
          end_port_(end_port),
          thread_count_(thread_count),
          timeout_ms_(timeout_ms) {
        for (int p = start_port_; p <= end_port_; ++p) {
            work_queue_.push(p);
        }
    }

    std::vector<ScanResult> run() {
        std::vector<std::thread> workers;
        workers.reserve(thread_count_);
        for (int i = 0; i < thread_count_; ++i) {
            workers.emplace_back(&PortScanner::worker_loop, this);
        }
        for (auto& t : workers) t.join();

        std::lock_guard<std::mutex> lock(results_mutex_);
        return results_;
    }

private:
    int next_port() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (work_queue_.empty()) return -1;
        int p = work_queue_.front();
        work_queue_.pop();
        return p;
    }

    void worker_loop() {
        int port;
        while ((port = next_port()) != -1) {
            ScanResult r = scan_port(port);
            if (r.open) {
                std::lock_guard<std::mutex> lock(results_mutex_);
                results_.push_back(std::move(r));
            }
        }
    }

    // Opens the connection in non-blocking mode and applies a timeout via
    // select(). On success, reads whatever bytes arrive first as the banner.
    ScanResult scan_port(int port) {
        ScanResult result{port, false, guess_service(port), ""};

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return result;

        // Switch to non-blocking mode
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));

        if (inet_pton(AF_INET, target_.c_str(), &addr.sin_addr) <= 0) {
            // Might be a hostname -> try DNS resolution
            hostent* he = gethostbyname(target_.c_str());
            if (!he) {
                close(sock);
                return result;
            }
            std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        }

        int conn_result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (conn_result < 0 && errno != EINPROGRESS) {
            close(sock);
            return result;
        }

        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        timeval tv{};
        tv.tv_sec = timeout_ms_ / 1000;
        tv.tv_usec = (timeout_ms_ % 1000) * 1000;

        int sel = select(sock + 1, nullptr, &write_fds, nullptr, &tv);
        if (sel <= 0) {
            close(sock);  // timeout or error -> treated as closed/filtered
            return result;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            close(sock);
            return result;
        }

        result.open = true;

        // Banner grabbing: wait briefly and read whatever arrives (we do not
        // send an active probe, we only passively listen for the service's
        // own initial response).
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        timeval read_tv{};
        read_tv.tv_sec = 0;
        read_tv.tv_usec = 300 * 1000;  // 300ms banner wait

        if (select(sock + 1, &read_fds, nullptr, nullptr, &read_tv) > 0) {
            char buf[512];
            ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                result.banner = std::string(buf, static_cast<size_t>(n));
            }
        }

        close(sock);
        return result;
    }

    std::string target_;
    int start_port_;
    int end_port_;
    int thread_count_;
    int timeout_ms_;

    std::queue<int> work_queue_;
    std::mutex queue_mutex_;

    std::vector<ScanResult> results_;
    std::mutex results_mutex_;
};

void print_json(const std::string& target, const std::vector<ScanResult>& results,
                 double elapsed_sec) {
    std::cout << "{\n";
    std::cout << "  \"target\": \"" << json_escape(target) << "\",\n";
    std::cout << "  \"elapsed_seconds\": " << elapsed_sec << ",\n";
    std::cout << "  \"open_ports\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        std::cout << "    {\n";
        std::cout << "      \"port\": " << r.port << ",\n";
        std::cout << "      \"service_guess\": \"" << json_escape(r.service_guess) << "\",\n";
        std::cout << "      \"banner\": \"" << json_escape(r.banner) << "\"\n";
        std::cout << "    }" << (i + 1 < results.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

}  // namespace train

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <target> <start_port> <end_port> [thread_count=200] [timeout_ms=500]\n";
        return 1;
    }

    std::string target = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port = std::atoi(argv[3]);
    int thread_count = argc > 4 ? std::atoi(argv[4]) : 200;
    int timeout_ms = argc > 5 ? std::atoi(argv[5]) : 500;

    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::cerr << "Error: port range must be within 1-65535 and start <= end.\n";
        return 1;
    }
    if (thread_count < 1) thread_count = 1;

    auto t0 = std::chrono::steady_clock::now();
    train::PortScanner scanner(target, start_port, end_port, thread_count, timeout_ms);
    auto results = scanner.run();
    auto t1 = std::chrono::steady_clock::now();

    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    // Sort by port number (thread completion order can vary)
    std::sort(results.begin(), results.end(),
              [](const train::ScanResult& a, const train::ScanResult& b) {
                  return a.port < b.port;
              });

    train::print_json(target, results, elapsed);
    return 0;
}
