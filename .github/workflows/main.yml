#!/usr/bin/env python3
# nullhex_portal_multiuser.py
# Multi-user login → Home → Practice Test + Flashcards + Cyber Chat (AI/offline) + Group Chat (rooms)
# Clean screen UX, personalized greetings, study suggestions, and file-persisted group chat.

import getpass
import sys
import time
import random
import os
import re
import json
from datetime import datetime

# -------------------
# Users database
# -------------------
USERS = {
    "colton henry": "112907",
    "ian oden": "casper",
    "anthony stewart": "blue",
    "aidan fisher": "foot",
}

# -------------------
# Files (persistence)
# -------------------
GROUP_CHAT_FILE = "nullhex_groupchat.json"  # { room: [ {user, text, ts} ] }

# -------------------
# Helpers
# -------------------
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def typewriter(text, delay=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def pause(seconds=2):
    time.sleep(seconds)

def first_name(username: str) -> str:
    return username.split()[0].capitalize() if username else "Friend"

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -------------------
# Quiz Questions (with topics for study suggestions)
# -------------------
QUESTIONS = [
    {
        "q": "Which of the following best describes 2FA?",
        "options": [
            ("A", "Using a password and a PIN"),
            ("B", "Using two different categories of evidence (know/have/are)"),
            ("C", "Using a password and security questions"),
            ("D", "Using a password plus a username"),
        ],
        "answer": "B",
        "explain": "2FA requires two different factor types. Password + security questions is just two 'something you know'.",
        "topic": "Identity & Access (2FA/MFA)",
    },
    {
        "q": "3DES was designed to replace which older cipher?",
        "options": [("A", "AES"), ("B", "DES"), ("C", "RSA"), ("D", "Blowfish")],
        "answer": "B",
        "explain": "Triple DES repeated DES three times to extend its life, but it's slow and outdated compared to AES.",
        "topic": "Cryptography (Block Ciphers)",
    },
    {
        "q": "The AAA security model stands for:",
        "options": [
            ("A", "Authentication, Access, Authorization"),
            ("B", "Authentication, Authorization, and Accounting"),
            ("C", "Authentication, Access, and Auditing"),
            ("D", "Availability, Authentication, Authorization"),
        ],
        "answer": "B",
        "explain": "AAA = Authenticate a subject, Authorize actions, and Account for activity.",
        "topic": "Identity & Access (AAA)",
    },
    {
        "q": "Which access control model bases decisions on attributes like time or device posture?",
        "options": [("A", "RBAC"), ("B", "DAC"), ("C", "ABAC"), ("D", "MAC")],
        "answer": "C",
        "explain": "ABAC evaluates attributes for fine-grained, context-aware decisions.",
        "topic": "Identity & Access (ABAC/RBAC)",
    },
    {
        "q": "In cryptography, what does AES-GCM add compared to plain AES?",
        "options": [
            ("A", "Higher key length only"),
            ("B", "Stream cipher conversion"),
            ("C", "Authenticated encryption (confidentiality + integrity)"),
            ("D", "Faster brute-force resistance"),
        ],
        "answer": "C",
        "explain": "AES-GCM (and CCM) are AEAD modes combining encryption and integrity with tags.",
        "topic": "Cryptography (AES/AEAD)",
    },
    {
        "q": "In IPsec, which protocol is usually chosen for confidentiality?",
        "options": [("A", "AH"), ("B", "ESP"), ("C", "IKE"), ("D", "TLS")],
        "answer": "B",
        "explain": "ESP encrypts and can authenticate. AH only authenticates headers.",
        "topic": "Networking Security (IPsec AH/ESP)",
    },
    {
        "q": "Which acronym refers to long-term, stealthy adversaries?",
        "options": [("A", "API"), ("B", "APT"), ("C", "ATT&CK"), ("D", "ARP")],
        "answer": "B",
        "explain": "APT = Advanced Persistent Threat.",
        "topic": "Threats (APT/ATT&CK)",
    },
    {
        "q": "Which protocol translates IP addresses to MAC addresses on a LAN?",
        "options": [("A", "ARP"), ("B", "DNS"), ("C", "DHCP"), ("D", "ICMP")],
        "answer": "A",
        "explain": "ARP resolves IP to MAC, but its design makes spoofing possible.",
        "topic": "Networking (ARP & LAN basics)",
    },
    {
        "q": "In business continuity, what is the role of a BCP compared to a DRP?",
        "options": [
            ("A", "DRP is broader than BCP"),
            ("B", "BCP covers business functions; DRP restores IT after disruption"),
            ("C", "BCP is optional; DRP is mandatory"),
            ("D", "They mean the same thing"),
        ],
        "answer": "B",
        "explain": "BCP ensures operations continue; DRP restores IT/data as a subset.",
        "topic": "Governance/Risk (BCP vs DRP)",
    },
    {
        "q": "Which Internet routing protocol is infamous for route leaks and hijacks?",
        "options": [("A", "RIP"), ("B", "OSPF"), ("C", "BGP"), ("D", "MPLS")],
        "answer": "C",
        "explain": "BGP mishaps can take down large parts of the Internet.",
        "topic": "Networking (BGP/Internet routing)",
    },
]

# -------------------
# Flashcards (15 terms)
# -------------------
FLASHCARDS = [
    ("2FA", "Two different factor types (know/have/are) to authenticate. Prefer app TOTP or hardware keys over SMS."),
    ("AAA", "Authenticate a subject, Authorize actions, and Account/log activity."),
    ("ABAC", "Access decisions using attributes (user, resource, context) — fits zero-trust."),
    ("ACL", "Allow/Deny entries attached to an object (files, buckets, routers). Order matters."),
    ("AES-GCM", "AES mode with authenticated encryption (confidentiality + integrity tags)."),
    ("AH vs ESP", "AH = auth/integrity only; ESP = encryption (and can auth). ESP for confidentiality."),
    ("APT", "Well-funded, persistent adversary running long campaigns with stealth."),
    ("ARP", "Resolves IP → MAC on LAN; vulnerable to spoofing without protections."),
    ("ATT&CK", "MITRE’s matrix of adversary tactics/techniques for detections and coverage."),
    ("BCP/DRP", "BCP keeps business running; DRP restores IT/data after disruption."),
    ("BGP", "Inter-domain routing; leaks/hijacks can cause global outages."),
    ("DKIM", "Email header signature validated via DNS public key; proves integrity/source."),
    ("DMARC", "Policy tying SPF+DKIM with actions (none/quarantine/reject) + reporting."),
    ("DNS", "Translates names to IPs; secure with DNSSEC; watch for tunneling/poisoning."),
    ("DHCP", "Hands out IP/gateway/DNS to clients; rogue servers can hijack traffic."),
]

# -------------------
# Offline AI Knowledge (keyword → answer)
# -------------------
OFFLINE_KB = {
    r"\b2fa|mfa|factor\b": (
        "2FA uses two different factor types (know/have/are). Strong picks: app TOTP or FIDO2 keys; avoid SMS when possible."
    ),
    r"\baaa\b|\bauthentication authorization accounting\b": (
        "AAA = Authentication, Authorization, Accounting. AuthN verifies identity; AuthZ decides actions; Accounting logs it."
    ),
    r"\babac\b|attribute[- ]based": (
        "ABAC makes decisions using attributes (user, resource, action, context). Powerful but needs governance/testing."
    ),
    r"\baes[- ]?gcm\b|\baead\b": (
        "AES-GCM = authenticated encryption. You get confidentiality + integrity. Never reuse nonces."
    ),
    r"\bah\b|\besp\b|ipsec": (
        "IPsec: AH authenticates headers; ESP encrypts (and can auth). ESP is typical for confidentiality; mind NAT-T."
    ),
    r"\bapt\b|persistent threat": (
        "APT: well-funded operators running multi-stage campaigns. Map detections to MITRE ATT&CK and harden identity paths."
    ),
    r"\barp\b": (
        "ARP resolves IP→MAC on LAN and is spoofable. Use Dynamic ARP Inspection, segmentation, and pervasive TLS."
    ),
    r"\bbcp\b|\bdrp\b|continuity": (
        "BCP keeps critical business functions running; DRP restores IT/data to meet RTO/RPO. Test both, not just backups."
    ),
    r"\bbgp\b|route leak|hijack": (
        "BGP security: filter prefixes, use ROAs/RPKI, monitor anomalies. Leaks/hijacks can cause global impact."
    ),
    r"\bdkim\b": (
        "DKIM signs email headers; receivers validate with DNS pubkey. It proves source/integrity but doesn't enforce policy."
    ),
    r"\bdmarc\b": (
        "DMARC layers on SPF+DKIM. Set policy to quarantine/reject once stable; review rua/ruf reports and alignment rules."
    ),
    r"\bdns\b|dnssec|doh|dot": (
        "DNS translates names↔IPs. DNSSEC adds authenticity. DoH/DoT encrypt queries; balance privacy with enterprise controls."
    ),
    r"\bdhcp\b": (
        "DHCP auto-assigns IP/gateway/DNS. Rogue DHCP can hijack; restrict who can serve, use port security."
    ),
    r"\bcve\b": (
        "CVE is an identifier for a vuln, not a severity. Pair with CVSS/environmental context to prioritize."
    ),
    r"\bcvss\b": (
        "CVSS scores severity (0–10). Great starting point; adjust for exposure and business impact."
    ),
    r"\bxss\b|cross[- ]site scripting": (
        "XSS runs attacker code in your page. Defend with output encoding, CSP, and avoiding unsafe inline JS."
    ),
    r"\bcsrf\b|xsrf|cross[- ]site request forgery": (
        "CSRF tricks a browser into sending authenticated requests. Use same-site cookies and anti-CSRF tokens."
    ),
}

# -------------------
# Greetings
# -------------------
GREETING_REGEX = re.compile(
    r"^\s*(hi|hey|hello|yo|sup|what's up|whats up|howdy|good (morning|afternoon|evening)|how are you|how r u|hru)\b.*$",
    re.IGNORECASE,
)

def greet_response(username: str) -> str:
    hour = time.localtime().tm_hour
    if hour < 12:
        tod = "morning"
    elif hour < 18:
        tod = "afternoon"
    else:
        tod = "evening"
    name = first_name(username)
    return (
        f"Hey {name}! Good {tod}. I’m here for cyber questions, drills, or quick tips.\n"
        "Try: “ESP vs AH?”, “ABAC vs RBAC example”, or “make me a 7-day crypto study plan.”"
    )

# -------------------
# Study suggestion engine
# -------------------
def suggest_from_results(missed_topics: dict) -> str:
    if not missed_topics:
        return "Suggestion: Nice work. Try a timed run or bump difficulty next."
    sorted_topics = sorted(missed_topics.items(), key=lambda kv: kv[1], reverse=True)
    top = [t for t, _ in sorted_topics[:2]]
    bullets = []
    for t in top:
        if "AES" in t or "Crypto" in t:
            bullets.append("Review AES modes (GCM/CCM), AEAD, and why nonce reuse is fatal.")
        elif "ABAC" in t or "AAA" in t or "Identity" in t:
            bullets.append("Compare ABAC vs RBAC; also revisit AAA and where accounting logs matter.")
        elif "IPsec" in t:
            bullets.append("Drill AH vs ESP, transport vs tunnel, and NAT-T behavior.")
        elif "ARP" in t or "Networking" in t:
            bullets.append("Refresh L2/L3 basics: ARP flow, spoofing risks, and mitigations (DAI/VLANs/TLS).")
        elif "BCP" in t or "Governance" in t:
            bullets.append("Revisit BCP vs DRP: definitions, RTO/RPO, and example scenarios.")
        elif "BGP" in t:
            bullets.append("Skim BGP risks (leaks/hijacks), RPKI/ROAs, and why global impact happens.")
        else:
            bullets.append(f"Take another pass at: {t}.")
    return "Suggestion: " + " ".join(bullets)

# -------------------
# Optional API bridge (OpenAI)
# -------------------
def try_openai_answer(prompt: str) -> str | None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI  # type: ignore # pip install openai
        client = OpenAI(api_key=api_key)
        system = ("You are a concise cybersecurity study tutor. Use plain language, define acronyms on first use, "
                  "and give practical examples. Keep answers under 8 sentences.")
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=400,
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return None

def offline_answer(prompt: str) -> str:
    q = prompt.lower()
    for pattern, answer in OFFLINE_KB.items():
        if re.search(pattern, q):
            return answer
    return ("Not seeing a direct hit. Try keywords like 2FA, AAA, ABAC, AES-GCM, ESP vs AH, APT, ARP, BCP/DRP, BGP, "
            "DKIM/DMARC, DNS/DNSSEC, DHCP, CVE/CVSS, XSS, CSRF — or ask 'why/how' with a short scenario.")

# -------------------
# Quiz (clean screen per question) — returns (score, missed_topics)
# -------------------
def run_quiz():
    questions = QUESTIONS[:]
    random.shuffle(questions)
    score = 0
    missed = {}

    for i, q in enumerate(questions, 1):
        opts = q["options"][:]
        random.shuffle(opts)
        mapping = {chr(ord("A")+idx): orig for idx, (orig, _t) in enumerate(opts)}

        clear_screen()
        print(f"Practice Test — Question {i}/{len(questions)}\n")
        print(q["q"])
        for idx, (_orig, text) in enumerate(opts):
            print(f"{chr(ord('A')+idx)}) {text}")

        ans = input("\nYour answer (A/B/C/D): ").strip().upper()
        correct = ans in mapping and mapping[ans] == q["answer"]

        clear_screen()
        print(f"Question {i}/{len(questions)}")
        if correct:
            print("✅ Correct!")
            score += 1
        else:
            print("❌ Wrong.")
            print(f"Why: {q['explain']}")
            missed[q["topic"]] = missed.get(q["topic"], 0) + 1
        input("\nPress ENTER for next...")

    clear_screen()
    print("Practice Test — Complete")
    print(f"Your final score: {score}/{len(questions)}")
    suggestion = suggest_from_results(missed)
    print("\n" + suggestion)
    input("\nPress ENTER to return to Home...")
    return score, missed

# -------------------
# Flashcards (clean screen per card + flip)
# -------------------
def run_flashcards():
    cards = FLASHCARDS[:]
    random.shuffle(cards)

    idx = 0
    show_definition = False
    while idx < len(cards):
        term, definition = cards[idx]
        clear_screen()
        print(f"Flashcards — Card {idx+1}/{len(cards)}")
        print("--------------------------------")
        print("Definition:\n" + definition if show_definition else "Term:\n" + term)

        print("\nControls: [ENTER=next]  [1=flip]  [q=quit]")
        cmd = input("> ").strip().lower()
        if cmd == "1":
            show_definition = not show_definition
        elif cmd == "q":
            clear_screen()
            print("Exiting flashcards...")
            time.sleep(0.6)
            return
        else:
            idx += 1
            show_definition = False

    clear_screen()
    print("Flashcards — Complete")
    input("\nPress ENTER to return to Home...")

# -------------------
# Cyber Chat (AI / offline fallback) — greets by name & handles greetings
# -------------------
def cyber_chat(username: str):
    clear_screen()
    print("Cyber Chat (AI)\n----------------")
    print("Ask anything about cybersecurity. Commands: /help  /quit")
    print("If OPENAI_API_KEY is set and 'openai' is installed, live AI will answer; otherwise, an offline helper replies.")
    time.sleep(0.6)

    while True:
        print()
        user = input(f"{first_name(username)}: ").strip()
        if not user:
            continue
        if user.lower() in ("/quit", "/q", "exit"):
            clear_screen()
            print("Leaving Cyber Chat...")
            time.sleep(0.5)
            return
        if user.lower() in ("/help", "help"):
            clear_screen()
            print("Cyber Chat Help\n---------------")
            print("• Ask focused questions: 'Explain ABAC vs RBAC with example', 'ESP vs AH?'.")
            print("• Try 'study plan for Security+ crypto in 7 days'.")
            print("• Commands: /quit to exit, /help for this screen.")
            continue

        if GREETING_REGEX.match(user):
            answer = greet_response(username)
        else:
            answer = try_openai_answer(user) or offline_answer(user)

        clear_screen()
        print("Cyber Chat (AI)\n----------------")
        print(f"You: {user}\n")
        print(answer)

# -------------------
# Group Chat (rooms, persisted to file)
# -------------------
def _load_chat_state():
    if not os.path.exists(GROUP_CHAT_FILE):
        return {}
    try:
        with open(GROUP_CHAT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_chat_state(state: dict):
    tmp = GROUP_CHAT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, GROUP_CHAT_FILE)

def _ensure_room(state: dict, room: str):
    if room not in state:
        state[room] = []

def _post_message(state: dict, room: str, user: str, text: str):
    _ensure_room(state, room)
    state[room].append({"user": user, "text": text, "ts": now_iso()})
    # cap room history to last 500 messages to keep file tidy
    if len(state[room]) > 500:
        state[room] = state[room][-500:]

def _list_rooms(state: dict):
    return sorted(state.keys())

def _print_room(room: str, messages: list, limit: int = 30):
    clear_screen()
    print(f"Group Chat — #{room}  (showing last {min(limit, len(messages))} of {len(messages)})")
    print("-" * 60)
    tail = messages[-limit:] if messages else []
    for m in tail:
        print(f"[{m['ts']}] {m['user']}: {m['text']}")
    print("-" * 60)
    print("Type to chat. Commands: /help  /rooms  /join <room>  /create <room>  /refresh  /me <action>  /quit")

def group_chat(username: str):
    state = _load_chat_state()
    current_room = "general"
    _ensure_room(state, current_room)

    # Announce join
    _post_message(state, current_room, "*system*", f"{first_name(username)} joined #{current_room}")
    _save_chat_state(state)

    while True:
        _print_room(current_room, state.get(current_room, []))
        msg = input(f"{first_name(username)} @ #{current_room}> ").strip()

        if not msg:
            continue
        if msg.lower() in ("/quit", "/q", "exit"):
            # Announce leave
            state = _load_chat_state()
            _post_message(state, current_room, "*system*", f"{first_name(username)} left #{current_room}")
            _save_chat_state(state)
            clear_screen()
            print("Leaving Group Chat...")
            time.sleep(0.5)
            return
        if msg.lower() in ("/help", "help"):
            clear_screen()
            print("Group Chat Help\n----------------")
            print("• /rooms — list rooms")
            print("• /join <room> — switch to a room (creates view if it exists)")
            print("• /create <room> — create a new room")
            print("• /refresh — reload messages")
            print("• /me <action> — emote (e.g., /me waves)")
            print("• /quit — leave chat")
            input("\nPress ENTER to return...")
            continue
        if msg.lower() == "/rooms":
            state = _load_chat_state()
            rooms = _list_rooms(state)
            clear_screen()
            print("Rooms\n-----")
            for r in rooms:
                print(f"# {r} ({len(state.get(r, []))} messages)")
            input("\nPress ENTER to return...")
            continue
        if msg.lower().startswith("/join "):
            room = msg.split(maxsplit=1)[1].strip().lstrip("#").lower()
            if not room:
                continue
            state = _load_chat_state()
            if room not in state:
                clear_screen()
                print(f"Room #{room} does not exist. Use /create", room, "to make it.")
                input("\nPress ENTER to return...")
                continue
            # leave current, join target
            _post_message(state, current_room, "*system*", f"{first_name(username)} left #{current_room}")
            current_room = room
            _post_message(state, current_room, "*system*", f"{first_name(username)} joined #{current_room}")
            _save_chat_state(state)
            continue
        if msg.lower().startswith("/create "):
            room = msg.split(maxsplit=1)[1].strip().lstrip("#").lower()
            if not room:
                continue
            state = _load_chat_state()
            if room in state:
                clear_screen()
                print(f"Room #{room} already exists.")
                input("\nPress ENTER to return...")
                continue
            _ensure_room(state, room)
            _post_message(state, room, "*system*", f"Room #{room} created by {first_name(username)}")
            # leave old room, join new
            _post_message(state, current_room, "*system*", f"{first_name(username)} left #{current_room}")
            current_room = room
            _post_message(state, current_room, "*system*", f"{first_name(username)} joined #{current_room}")
            _save_chat_state(state)
            continue
        if msg.lower() == "/refresh":
            state = _load_chat_state()
            continue
        if msg.lower().startswith("/me "):
            action = msg[4:].strip()
            if action:
                state = _load_chat_state()
                _post_message(state, current_room, f"*{first_name(username)}*", action)
                _save_chat_state(state)
            continue

        # Normal message
        state = _load_chat_state()
        _post_message(state, current_room, first_name(username), msg)
        _save_chat_state(state)

# -------------------
# Home Menu
# -------------------
def home_page(username):
    last_score = None
    last_missed = {}
    while True:
        clear_screen()
        print("-------------------------------------------")
        print(f"--- NullHex Home — Logged in as: {username} ---")
        if last_score is not None:
            print(f"Last score: {last_score}/{len(QUESTIONS)}")
            print(suggest_from_results(last_missed))
        print("-------------------------------------------")
        print("1) Practice Test")
        print("2) Flashcards")
        print("3) Cyber Chat (AI)")
        print("4) Group Chat")
        print("5) Sign Out")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            last_score, last_missed = run_quiz()
        elif choice == "2":
            run_flashcards()
        elif choice == "3":
            cyber_chat(username)
        elif choice == "4":
            group_chat(username)
        elif choice == "5":
            clear_screen()
            print("Signing out... Goodbye!")
            time.sleep(0.6)
            break
        else:
            print("Invalid choice.")
            time.sleep(0.8)

# -------------------
# Login Flow
# -------------------
def login():
    pause(2)
    typewriter("Welcome...")
    time.sleep(0.5)
    typewriter("Welcome to NullHex")

    name = input("\nPlease enter name: ").strip().lower()
    if name not in USERS:
        print("Access denied. (Unknown user)")
        return

    pwd = getpass.getpass(prompt="Password: ")
    if pwd == USERS[name]:
        typewriter(f"Access granted. Welcome {name}!")
        time.sleep(0.6)
        home_page(name)
    else:
        print("Access denied. (Wrong password)")

# -------------------
# Main
# -------------------
if __name__ == "__main__":
    login()
