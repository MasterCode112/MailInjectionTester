# EmailPayloadForge

> Email injection & parameter pollution payload generator for bug bounty and authorized penetration testing.

---

## ⚠️ Ethical Usage Disclaimer

This tool is intended **strictly for**:
- Bug bounty programs where email endpoints are **in scope**
- Systems you **own** or have **explicit written authorization** to test

**Never** run this against production systems or accounts without permission. Unauthorized testing is illegal under laws such as the CFAA (US), Computer Misuse Act (UK), and equivalents globally.

---

## What it tests

| Vulnerability class | Description |
|---|---|
| Email header injection | CRLF sequences inject Bcc/Cc/Reply-To headers |
| Parameter pollution | Sending duplicate or array-type email fields |
| Type confusion | Array vs string, object vs string mismatches |
| OTP/reset to multiple recipients | Logic flaw allowing notification to attacker |
| JSON injection | Breaking out of JSON string context |
| Encoding bypass | Double-encoding, null bytes, Unicode separators |

---

## Installation

### Python CLI

```bash
# No dependencies required (stdlib only)
python3 email_payload_forge.py -o victim@target.com -a attacker@gmail.com
```

**Options:**

| Flag | Description |
|---|---|
| `-o` | Original/target email address |
| `-a` | Attacker/collector email |
| `-f CATEGORY` | Filter output by category name |
| `-e output.txt` | Export payloads to .txt file |
| `--list-cats` | List all categories and counts |

**Examples:**

```bash
# Generate all payloads
python3 email_payload_forge.py -o victim@target.com -a attacker@gmail.com

# Filter to CRLF injection only
python3 email_payload_forge.py -o victim@target.com -a attacker@gmail.com -f "CRLF Bcc"

# Export for Burp Intruder
python3 email_payload_forge.py -o victim@target.com -a attacker@gmail.com -e payloads.txt
```

---

### Burp Suite Extension

**Requirements:**
- Burp Suite Pro or Community
- Jython standalone JAR (≥ 2.7.3)

**Setup:**
1. Download [Jython standalone JAR](https://www.jython.org/download)
2. In Burp: `Extender > Options > Python Environment` → set JAR path
3. `Extender > Extensions > Add`
   - Extension type: **Python**
   - File: `EmailPayloadForge_burp.py`
4. The **EmailPayloadForge** tab appears in Burp

**Usage:**
1. Intercept a password-reset or sign-up request in Proxy
2. Right-click → **Send to EmailPayloadForge**
3. Set target email, attacker email, and parameter name in the tab
4. Click **Generate & preview payloads** to populate the table
5. For automated sending, open the Python console and call:
   ```python
   burpCallbacks.getExtension("EmailPayloadForge").send_all()
   ```
6. Results (status, length, reflection) update in the table
7. Entries marked **REFLECTED=YES** are high-priority findings

---

## Using payloads in Burp Intruder

1. Export `.txt` with `-e payloads.txt`
2. Send target request to Intruder
3. Highlight the email parameter value → **Add §**
4. Payloads tab → **Simple list** → Paste from file
5. Run attack; sort by Response Length or grep for attacker email

---

## Response analysis indicators

| Signal | Meaning |
|---|---|
| Attacker email in response body | Reflection — likely OTP/link sent to attacker |
| Status 200 vs 400/422 | Payload bypassed validation |
| Response length change | Different code path triggered |
| Duplicate email in logs | Both addresses received notification |

---

## Project name

**EmailPayloadForge** — `github.com/yourhandle/EmailPayloadForge`

Alternative names: `MailInjectionTester`, `HeaderSmith`, `MailBreaker`

---

## License

MIT — for authorized security research only.
