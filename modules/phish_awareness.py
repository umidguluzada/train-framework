"""
TRAIN Framework - modules/phish_awareness.py
Text-only phishing awareness / training content.

Registers:
  phish-awareness [level]    -> shows a random example email + red flags
                                 (level: easy|medium|hard|critical|any, default any)
  phish-quiz [count] [level] -> an interactive "spot the phish" quiz
                                 (default 5 questions, level defaults to "any")

This module is intentionally text-only: it never generates a fake login
page, never collects credentials, and never sends real email or links.
It is meant for security-awareness training - the same kind of content a
blue team would put in a slide deck or an internal wiki - just presented
interactively in the TUI. If you need a full click-tracking phishing
simulation for an actual training campaign, use a purpose-built platform
with proper consent/opt-in tracking (e.g. GoPhish) rather than this
module.

Difficulty levels (roughly matching how hard the lure is to spot):
  easy      - blatant: bad grammar, absurd promises, obvious mismatched sender
  medium    - plausible business email, but with a couple of clear tells
  hard      - well-written, context-appropriate, subtle tells only
  critical  - highly targeted "spear phishing" style, minimal tells,
              relies on specific/personal-sounding context
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

LEVELS = ["easy", "medium", "hard", "critical"]


@dataclass
class PhishExample:
    subject: str
    sender: str
    body: str
    is_phishing: bool
    level: str  # "easy" | "medium" | "hard" | "critical"
    red_flags: list[str]


# All example emails below are fictional and self-contained - no real
# brand names or real URLs, so nothing here could be mistaken for (or
# reused as) an actual lure.
EXAMPLES: list[PhishExample] = [

    # ---------------------------------------------------------------- EASY
    PhishExample(
        subject="CONGRATULATION!!! You Are WINNER of $1,000,000",
        sender="claims-office@lottery-international-winners.example",
        body=(
            "Dear Lucky Winner,\n\n"
            "We are pleased to inform you that you have WON the sum of "
            "$1,000,000.00 USD in our international email lottery. To "
            "release your fund, kindly send your full name, address, "
            "phone number and a processing fee of $150 via wire transfer."
        ),
        is_phishing=True, level="easy",
        red_flags=[
            "You never entered a lottery you're claiming to have won",
            "Asks for an upfront 'processing fee' before releasing money",
            "Poor grammar and excessive punctuation/capitalization",
            "Generic, non-specific sender with no real organization behind it",
        ],
    ),
    PhishExample(
        subject="Weekly team standup - Wednesday 9am",
        sender="scrum-master@company-internal.example",
        body="Reminder: standup is at 9am Wednesday, same Zoom link as always. Please have your updates ready.",
        is_phishing=False, level="easy", red_flags=[],
    ),
    PhishExample(
        subject="your Paypal acount has ben limited plz verify",
        sender="service@paypa1-secure-verification.example",
        body="we detect some problem whit your acount plese click link and confirm you're informations imediately or acount will be delete permanent",
        is_phishing=True, level="easy",
        red_flags=[
            "Multiple spelling and grammar errors throughout",
            "Sender domain uses a '1' instead of 'l' (paypa1) - classic typosquatting",
            "Vague 'some problem' with no specific detail",
            "Threatens permanent account deletion to force quick action",
        ],
    ),
    PhishExample(
        subject="Company holiday schedule 2026",
        sender="hr@company-internal.example",
        body="Attached is the finalized holiday schedule for 2026, same as discussed in last week's all-hands.",
        is_phishing=False, level="easy", red_flags=[],
    ),
    PhishExample(
        subject="FINAL NOTICE: Your computer has a VIRUS",
        sender="alert@windows-security-center-warning.example",
        body="WARNING! Our scan detected 5 viruses on your computer. Call 1-800-XXX-XXXX IMMEDIATELY or click here to download our removal tool.",
        is_phishing=True, level="easy",
        red_flags=[
            "An email cannot scan your computer for viruses",
            "Fake urgency with all-caps warnings",
            "Asks you to call an unverified number or download an unknown tool",
            "Not from any real, identifiable security vendor",
        ],
    ),
    PhishExample(
        subject="Parking garage closed this weekend",
        sender="facilities@company-internal.example",
        body="Heads up - the parking garage will be closed Sat-Sun for resurfacing. Street parking is available nearby.",
        is_phishing=False, level="easy", red_flags=[],
    ),
    PhishExample(
        subject="Re: Re: Re: FWD: Investment opportunity - act now!!",
        sender="prince.investment@overseas-business-fund.example",
        body="Greetings Dear Friend, I am a bank official with access to $10.5 million dormant funds. I need your assistance to transfer this money and will share 40% with you.",
        is_phishing=True, level="easy",
        red_flags=[
            "Classic 'advance-fee' scam narrative (unrealistic windfall)",
            "Requests your bank account details upfront",
            "Multiple forwarded 'Re:/FWD:' subject line - a common spam pattern",
            "No legitimate business would contact a stranger this way",
        ],
    ),
    PhishExample(
        subject="Lunch order for Friday - reply with your pick",
        sender="office-manager@company-internal.example",
        body="Ordering lunch for Friday's planning session. Reply with your choice from the usual menu by Wednesday.",
        is_phishing=False, level="easy", red_flags=[],
    ),
    PhishExample(
        subject="YOU HAVE BEEN SELECTED - claim free iPhone now!!!",
        sender="promo@free-gadgets-giveaway-2026.example",
        body="You are today's LUCKY VISITOR! Click NOW to claim your FREE iPhone 17! Only 3 left!! Offer expires in 10 MINUTES!!!",
        is_phishing=True, level="easy",
        red_flags=[
            "You didn't sign up for any giveaway or visit a related site",
            "Extreme, manufactured urgency (10-minute countdown)",
            "Excessive exclamation points and capitalization",
            "'Free premium product' offers like this are a classic scam pattern",
        ],
    ),
    PhishExample(
        subject="Office supplies restock - let facilities know what you need",
        sender="facilities@company-internal.example",
        body="Monthly supply restock is happening Thursday. Reply to this email if there's anything specific you need at your desk.",
        is_phishing=False, level="easy", red_flags=[],
    ),

    # -------------------------------------------------------------- MEDIUM
    PhishExample(
        subject="URGENT: Your account will be suspended in 24 hours",
        sender="security-alert@accounts-verify-support.example",
        body="Dear Valued Customer, we detected unusual activity on your account. To avoid permanent suspension, verify your identity immediately by clicking the link below and entering your login credentials. You have 24 hours to comply.",
        is_phishing=True, level="medium",
        red_flags=[
            "Urgency/fear tactic (24-hour deadline)",
            "Generic greeting ('Valued Customer' instead of your name)",
            "Sender domain doesn't match any real company you'd expect",
            "Asks you to click a link and enter credentials directly",
        ],
    ),
    PhishExample(
        subject="Q3 team lunch - RSVP by Friday",
        sender="maria.chen@company-internal.example",
        body="Planning our quarterly team lunch for next Friday at 12:30pm. Please reply with your food preference by Thursday EOD.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Invoice #48213 attached - payment overdue",
        sender="billing@supplier-invoices-portal.example",
        body="Please find attached invoice #48213, now 15 days overdue. Open the attachment and enable macros to view the full invoice details and remit payment.",
        is_phishing=True, level="medium",
        red_flags=[
            "Asks you to enable macros (classic malware delivery technique)",
            "Unexpected invoice with no prior purchase order context",
            "Sender domain is generic/unfamiliar, not the actual vendor's domain",
            "Creates pressure via 'overdue' framing",
        ],
    ),
    PhishExample(
        subject="Your package delivery attempt failed",
        sender="delivery-updates@parcel-tracking-service.example",
        body="We attempted to deliver your package today. To reschedule, confirm your address and pay a small redelivery fee ($1.99) using the link below within 48 hours.",
        is_phishing=True, level="medium",
        red_flags=[
            "Small, easy-to-approve payment request (common tactic)",
            "Time pressure (48-hour window)",
            "You weren't necessarily expecting a package",
            "Generic carrier name, no tracking number you recognize",
        ],
    ),
    PhishExample(
        subject="Reminder: password rotation due next week",
        sender="it-helpdesk@company-internal.example",
        body="As part of our normal quarterly rotation, please update your password via the internal portal before next Monday.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="You've won! Claim your $500 gift card now",
        sender="rewards-team@prize-notification-center.example",
        body="Congratulations! Your email was randomly selected to receive a $500 gift card. Click below and complete a short survey with your name, address, and card details to claim your prize within 3 hours.",
        is_phishing=True, level="medium",
        red_flags=[
            "Unsolicited prize you never entered to win",
            "Asks for personal and card details to 'claim' something free",
            "Artificial urgency (3-hour expiration)",
            "Generic sender with no verifiable company name",
        ],
    ),
    PhishExample(
        subject="Conference room B booked for design review",
        sender="facilities@company-internal.example",
        body="Confirming Room B is booked for the design review, Thursday 2-3pm. Let facilities know if you need the projector changed.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Microsoft 365 storage almost full",
        sender="notifications@ms365-storage-alert.example",
        body="Your mailbox is at 98% capacity. Emails will stop sending and receiving in 24 hours unless you verify your account and upgrade your storage plan now.",
        is_phishing=True, level="medium",
        red_flags=[
            "Sender domain isn't a real Microsoft domain",
            "Creates urgency around a service disruption",
            "Asks you to 'verify your account' - a common credential-harvesting phrase",
            "Real storage warnings link to the official app/portal, not an external link",
        ],
    ),
    PhishExample(
        subject="New comment on your shared document",
        sender="notifications@company-docs.example",
        body="Someone commented on 'Q3 Roadmap.docx' that you have access to. Open the document to view and reply.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Job offer: remote data entry, $45/hr, start today",
        sender="hr-recruiting@career-opportunity-team.example",
        body="Congratulations, you've been selected for a remote data entry position paying $45/hr. No interview required. Reply with your full name, address, and a copy of your ID.",
        is_phishing=True, level="medium",
        red_flags=[
            "Unrealistically high pay for the stated role with no interview",
            "Requests a copy of your government ID over email upfront",
            "You never applied for this position",
            "Legitimate hiring never skips interviews entirely",
        ],
    ),
    PhishExample(
        subject="Reminder: benefits enrollment closes Friday",
        sender="hr-benefits@company-internal.example",
        body="Open enrollment for benefits closes this Friday at 5pm. Log in to the usual HR portal (same link as last year) to update your selections.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Your subscription payment failed - update billing",
        sender="billing-support@streaming-service-account.example",
        body="We were unable to process your last payment. Update your billing information within 24 hours to avoid service interruption.",
        is_phishing=True, level="medium",
        red_flags=[
            "Generic streaming service name, not a specific company you actually subscribe to",
            "Pressures you to re-enter full card details via an email link",
            "24-hour urgency window",
            "Real billing issues are also shown inside the actual app when you log in",
        ],
    ),
    PhishExample(
        subject="Welcome to the team - onboarding checklist",
        sender="onboarding@company-internal.example",
        body="Welcome aboard! Complete your I-9 in the HR portal, set up your laptop with IT during your 10am appointment, and join #new-hires.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Server maintenance window this weekend",
        sender="infra-team@company-internal.example",
        body="Scheduled maintenance on staging Saturday 10pm-2am. Staging will be unreachable during that window. Production is unaffected.",
        is_phishing=False, level="medium", red_flags=[],
    ),
    PhishExample(
        subject="Tax refund pending - claim before deadline",
        sender="refund-processing@tax-authority-notice.example",
        body="Our records show you are eligible for a tax refund. To receive your refund, submit your bank account and Social Security number through the secure form below.",
        is_phishing=True, level="medium",
        red_flags=[
            "Real tax authorities do not request bank/SSN details via email",
            "Generic 'tax authority' sender, not your actual government agency's domain",
            "Combines urgency (deadline) with a financial reward",
            "Asks for highly sensitive identity information over email",
        ],
    ),

    # ---------------------------------------------------------------- HARD
    PhishExample(
        subject="Re: Wire transfer needed today - confidential",
        sender="ceo.office@company-exec-mail.example",
        body="I'm in back-to-back meetings and can't call. I need you to process an urgent wire transfer to a new vendor today. Keep this confidential for now, I'll explain later.",
        is_phishing=True, level="hard",
        red_flags=[
            "Business Email Compromise (BEC) pattern: authority + urgency + secrecy",
            "Requests confidentiality to prevent verification with others",
            "Sender domain mimics a real company but isn't the actual one",
            "Unusual, time-pressured financial request outside normal process",
        ],
    ),
    PhishExample(
        subject="Standup notes - Tuesday",
        sender="devteam-notes@company-internal.example",
        body="Quick recap: API migration on track for Friday, staging bug fixed (PR #482), sprint planning moved to 10am tomorrow.",
        is_phishing=False, level="hard", red_flags=[],
    ),
    PhishExample(
        subject="Action required: update your direct deposit info",
        sender="payroll-updates@hr-selfservice-portal.example",
        body="Our payroll system is migrating to a new provider. Please log in via the link below within 48 hours to re-enter your bank account and routing number.",
        is_phishing=True, level="hard",
        red_flags=[
            "Requests sensitive bank details via an emailed link",
            "Time pressure tied to a paycheck delay threat",
            "Real payroll migrations are normally announced in advance through official channels first",
            "Sender domain isn't the company's actual HR system domain",
        ],
    ),
    PhishExample(
        subject="IT Security: suspicious login blocked - verify now",
        sender="alerts@it-security-notice.example",
        body="We blocked a login attempt to your account from an unrecognized device in another country. Click here immediately to secure your account, or it will be locked within 2 hours.",
        is_phishing=True, level="hard",
        red_flags=[
            "Fear-based framing ('blocked login', 'locked as a precaution')",
            "Very short window to act (2 hours)",
            "Generic 'IT Security' sender, not your actual company's real domain",
            "Legit security alerts usually name the specific service/app affected",
        ],
    ),
    PhishExample(
        subject="Lunch and learn: intro to threat modeling - Thursday",
        sender="security-team@company-internal.example",
        body="Join us Thursday at noon for a lunch-and-learn on threat modeling basics. Pizza provided, no RSVP needed.",
        is_phishing=False, level="hard", red_flags=[],
    ),
    PhishExample(
        subject="Unusual sign-in activity - verify it was you",
        sender="account-security@cloud-storage-alerts.example",
        body="We noticed a sign-in from a new location. If this was you, no action is needed. If not, click below immediately before further action is taken automatically.",
        is_phishing=True, level="hard",
        red_flags=[
            "Vague, unnamed cloud provider - not a specific, verifiable service",
            "'Automatic action' framing pressures quick clicking without checking",
            "No details given about the sign-in (device, location) to actually verify",
            "Legit alerts usually let you check activity directly in the app, not via email link",
        ],
    ),
    PhishExample(
        subject="DocuSign: You have a document to sign",
        sender="no-reply@docusign-esignature-notice.example",
        body="You have a pending document requiring your signature. This document will expire in 24 hours. Log in with your email and password to view it securely.",
        is_phishing=True, level="hard",
        red_flags=[
            "Domain mimics a real e-signature provider but isn't the official one",
            "Asks you to log in with email/password just to 'view' a document",
            "You weren't expecting a document from this sender",
            "Artificial expiration urgency",
        ],
    ),
    PhishExample(
        subject="Quick question about the client call notes",
        sender="james.okafor@company-internal.example",
        body="Hey, did we capture the follow-up items from yesterday's client call? Want to make sure procurement has the timeline before Friday.",
        is_phishing=False, level="hard", red_flags=[],
    ),
    PhishExample(
        subject="Updated NDA for review - please sign by EOD",
        sender="legal-docs@partner-agreements-portal.example",
        body="Attached is the updated NDA from our legal team ahead of tomorrow's vendor meeting. Please review and sign using the portal link (single sign-on works as always) by end of day.",
        is_phishing=True, level="hard",
        red_flags=[
            "Domain resembles a legal/partner portal but isn't your company's actual one",
            "References an SSO login flow to make a fake portal seem legitimate",
            "Same-day deadline discourages careful verification",
            "No prior context confirming an NDA was actually expected",
        ],
    ),
    PhishExample(
        subject="Two-factor authentication re-enrollment required",
        sender="security@company-authenticator-service.example",
        body="Due to a recent security upgrade, all employees must re-enroll their two-factor authentication device within 72 hours via the link below.",
        is_phishing=True, level="hard",
        red_flags=[
            "Sender domain doesn't match the company's actual identity provider",
            "Legitimate 2FA re-enrollment is normally initiated inside the actual auth app, not via email link",
            "72-hour deadline applied broadly to 'all employees' without specifics",
            "Asks you to 'confirm' your phone number - a pretext for number harvesting",
        ],
    ),

    # ------------------------------------------------------------ CRITICAL
    PhishExample(
        subject="Following up from the conference - great meeting you",
        sender="daniel.reyes@industry-partners-summit.example",
        body="Hi, great connecting at the summit last week. As discussed, here's the partnership proposal - would love your thoughts before I present it internally Monday. Shared via this secure link (same login as any shared doc).",
        is_phishing=True, level="critical",
        red_flags=[
            "References a plausible-sounding but unverifiable shared past event ('the summit')",
            "No way to confirm this conversation actually happened",
            "Uses a 'secure link' phrase to make a credential-harvesting page sound routine",
            "Time pressure (Monday deadline) discourages checking with the sender directly",
        ],
    ),
    PhishExample(
        subject="Following up on your PTO request",
        sender="hr-benefits@company-internal.example",
        body="Your PTO request for next month has been approved. Calendar invite to follow from your manager as usual.",
        is_phishing=False, level="critical", red_flags=[],
    ),
    PhishExample(
        subject="Can you approve this before I head into back-to-back calls?",
        sender="sarah.kim.vp@company-executives.example",
        body="Hey, I know this is last minute but I need you to approve the attached PO before 2pm - I'm heading into calls. Same approval process as always, just need your sign-off today.",
        is_phishing=True, level="critical",
        red_flags=[
            "Sender domain subtly differs from the real company domain (executives vs internal)",
            "Uses a plausible, specific-sounding but unverifiable excuse for unavailability",
            "Tight, same-day deadline discourages a quick phone/Slack confirmation",
            "References 'same process as always' to lower suspicion without giving verifiable detail",
        ],
    ),
    PhishExample(
        subject="Re: Budget numbers you asked for",
        sender="finance-team@company-internal.example",
        body="Attached the Q3 numbers you asked for in this morning's planning meeting. Let me know if the breakdown by region works.",
        is_phishing=False, level="critical", red_flags=[],
    ),
    PhishExample(
        subject="Confirming our call - sending the agenda now",
        sender="alex.morgan@vendor-solutions-partners.example",
        body="Looking forward to our call Thursday. Attaching the agenda and a quick pre-read referencing the pricing tiers we discussed with your procurement team last quarter.",
        is_phishing=True, level="critical",
        red_flags=[
            "References a plausible but unverifiable prior interaction with 'your procurement team'",
            "Sender domain is generic/unfamiliar despite sounding like an established vendor",
            "Relies entirely on social proof (implied familiarity) rather than any hard verification",
            "Attachment framed as a routine pre-read to lower guard before opening it",
        ],
    ),
    PhishExample(
        subject="Payroll adjustment - please confirm before Friday's run",
        sender="payroll@company-internal.example",
        body="Small correction to your October timesheet is pending approval before Friday's payroll run - approve in the usual system when you get a chance.",
        is_phishing=False, level="critical", red_flags=[],
    ),
    PhishExample(
        subject="Your badge access was flagged - quick verification needed",
        sender="security-ops@company-facilities-access.example",
        body="Building security flagged an access anomaly on your badge this morning. To avoid a temporary hold on your access, confirm your employee ID and department via the form below before end of day.",
        is_phishing=True, level="critical",
        red_flags=[
            "Physical-security pretext is unusual and hard to independently verify quickly",
            "Sender domain is close to, but not exactly, the real facilities/security domain",
            "Same-day deadline paired with a 'hold on access' consequence creates pressure",
            "Asks for employee ID/department - useful for further targeted attacks, not just 'verification'",
        ],
    ),
    PhishExample(
        subject="Draft press release - need your eyes before it goes out",
        sender="comms-team@company-internal.example",
        body="Draft is attached for the product announcement - main thing to check is the customer quote section. Planning to send to PR by Thursday.",
        is_phishing=False, level="critical", red_flags=[],
    ),
    PhishExample(
        subject="Re: Following up from yesterday, one more thing",
        sender="michael.tran@company-internal-support.example",
        body="One more thing from our chat yesterday - can you resend the shared drive link when you get a sec? Mine seems to have expired and I want to finish the review before the deadline.",
        is_phishing=True, level="critical",
        red_flags=[
            "References a vague, unverifiable prior conversation ('our chat yesterday')",
            "Sender domain has an extra word ('internal-support') not matching the real internal domain",
            "Casual, low-pressure tone specifically designed to avoid triggering suspicion",
            "Goal (getting you to share/resend a link) is disguised as a small, harmless favor",
        ],
    ),
]


def _filter_by_level(level: str) -> list[PhishExample]:
    if level == "any":
        return EXAMPLES
    return [e for e in EXAMPLES if e.level == level]


def _level_style(level: str) -> str:
    return {
        "easy": "green",
        "medium": "yellow",
        "hard": "red",
        "critical": "red bold",
    }.get(level, "white")


def _render_example(ex: PhishExample, reveal: bool) -> None:
    level_style = _level_style(ex.level)
    body_panel = Panel(
        f"[bold]From:[/bold] {ex.sender}\n[bold]Subject:[/bold] {ex.subject}\n\n{ex.body}",
        title=f"Sample Message  [{level_style}]({ex.level.upper()})[/{level_style}]",
        border_style="cyan",
    )
    console.print(body_panel)

    if reveal:
        verdict = "[red bold]PHISHING[/red bold]" if ex.is_phishing else "[green bold]LEGITIMATE[/green bold]"
        console.print(f"\nVerdict: {verdict}\n")
        if ex.red_flags:
            table = Table(title="Red Flags")
            table.add_column("#", justify="right")
            table.add_column("Indicator")
            for i, flag in enumerate(ex.red_flags, 1):
                table.add_row(str(i), flag)
            console.print(table)
        else:
            console.print("[dim]No red flags - this is a normal, legitimate message.[/dim]")


@register_command("phish-awareness")
def cmd_phish_awareness(session: Session, args: list[str]) -> None:
    """Usage: phish-awareness [easy|medium|hard|critical]   (default: any level)"""
    level = args[0].lower() if args else "any"
    if level != "any" and level not in LEVELS:
        console.print(f"[red]Unknown level:[/red] {level}  (use: {', '.join(LEVELS)}, or omit for any)")
        return

    pool = _filter_by_level(level)
    if not pool:
        console.print(f"[yellow]No examples found for level '{level}'.[/yellow]")
        return

    example = random.choice(pool)
    _render_example(example, reveal=True)


@register_command("phish-quiz")
def cmd_phish_quiz(session: Session, args: list[str]) -> None:
    """
    Usage: phish-quiz [count] [easy|medium|hard|critical]
    Examples:
      phish-quiz              -> 5 questions, any level
      phish-quiz 10           -> 10 questions, any level
      phish-quiz 8 hard       -> 8 questions, hard level only
      phish-quiz all critical -> every critical-level example, in random order
    """
    count_arg = args[0] if len(args) >= 1 else "5"
    level = args[1].lower() if len(args) >= 2 else "any"

    if level != "any" and level not in LEVELS:
        console.print(f"[red]Unknown level:[/red] {level}  (use: {', '.join(LEVELS)}, or omit for any)")
        return

    pool = _filter_by_level(level)
    if not pool:
        console.print(f"[yellow]No examples found for level '{level}'.[/yellow]")
        return

    if count_arg.lower() == "all":
        count = len(pool)
    else:
        try:
            count = max(1, min(len(pool), int(count_arg)))
        except ValueError:
            console.print("[red]Count must be a number or 'all'.[/red]")
            return

    quiz_pool = random.sample(pool, k=count)  # fresh random subset+order every run
    correct = 0

    level_label = "any level" if level == "any" else f"'{level}' level only"
    console.print(Panel(
        f"[bold]{count}-question phishing awareness quiz[/bold] ({level_label})\n"
        f"For each message, decide: phishing or legitimate? "
        f"(pool of {len(pool)} matching examples, shuffled each run)",
        border_style="magenta",
    ))

    for i, ex in enumerate(quiz_pool, 1):
        console.print(f"\n[bold]Question {i}/{count}[/bold]")
        _render_example(ex, reveal=False)
        try:
            answer = input("Your answer (phishing/legit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Quiz cancelled.[/dim]")
            return

        user_said_phishing = answer.startswith("p")
        if user_said_phishing == ex.is_phishing:
            console.print("[green]Correct![/green]")
            correct += 1
        else:
            console.print("[red]Not quite.[/red]")

        verdict = "[red bold]PHISHING[/red bold]" if ex.is_phishing else "[green bold]LEGITIMATE[/green bold]"
        console.print(f"Answer: {verdict}")
        if ex.red_flags:
            for flag in ex.red_flags:
                console.print(f"  - {flag}")

    console.print(f"\n[bold]Score: {correct}/{count}[/bold]")
