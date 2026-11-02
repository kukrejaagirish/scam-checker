# scam-checker

[![Tests](https://github.com/kukrejaagirish/scam-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/kukrejaagirish/scam-checker/actions/workflows/tests.yml)

Paste an SMS or WhatsApp message and find out if it looks like a common Indian scam.

## Why

Every day people in India get messages like "your bank account will be blocked, update KYC",
"you are under digital arrest", or "earn ₹3000 per day by liking videos". Many people,
especially parents and first-time smartphone users, can't easily tell these apart from real
messages, and one wrong click or one shared OTP can empty a bank account.

scam-checker reads the message and points out the warning signs in plain words, then tells you
exactly what to do next.

## Features

- Detects common Indian scam patterns:
  - Digital arrest / fake police, CBI, customs
  - UPI collect or refund requests ("enter PIN to receive money")
  - KYC update / bank account, SIM or electricity blocked
  - Fake parcel, courier or customs
  - Job, task and part-time earning scams
  - Lottery, prize and lucky draw
  - Requests to share OTP, PIN or CVV
  - Suspicious links (short links, look-alike bank domains, `.apk` downloads)
  - Requests to install screen-sharing apps (AnyDesk, TeamViewer)
  - Urgency / pressure words
- Understands common Hinglish words such as "turant", "khata band", "giraftaar", "galti se", "ghar baithe".
- Understands Hindi written in Devanagari too, for every scam type above (for example "डिजिटल अरेस्ट",
  "खाता बंद", "केवाईसी", "यूपीआई पिन", "घर बैठे कमाएं", "ओटीपी बताओ"). Messages that mix Hindi and
  English are handled as well. Spelling variants with or without the nukta ("गिरफ़्तार" / "गिरफ्तार")
  and invisible zero-width characters that some keyboards add are treated the same.
- Gives a risk level (Low / Medium / High), a score out of 100, the reasons, and what to do.
- Pure Python 3 standard library. No API keys, no internet needed, nothing is sent anywhere.
- Patterns are kept as data in `scam_checker/detector.py`, so adding a new scam type is one entry.

## Install

Requires Python 3.8 or newer.

```bash
git clone https://github.com/kukrejaagirish/scam-checker.git
cd scam-checker
```

No other installation is needed.

## Usage

Pass the message as an argument:

```bash
python -m scam_checker "Your SBI account will be blocked today. Update KYC now"
```

For long or multi-line messages, run it without a message, paste the text, then press
Ctrl+D (on Windows: Ctrl+Z, then Enter). It reads the message from standard input:

```bash
python -m scam_checker
```

Get JSON output for use in other programs:

```bash
python -m scam_checker --json "Share the OTP you received"
```

The exit code is `0` for Low risk and `1` for Medium or High risk.

Use it from Python:

```python
from scam_checker import analyze

result = analyze("Aapka khata band ho jayega, turant KYC update karein")
print(result.level, result.score)
for match in result.matches:
    print("-", match.name)
```

## Example

**Example input** (a made-up scam message, for illustration only):

```text
Dear customer your SBI account will be blocked today. Update KYC turant: http://sbi-kyc-update.xyz/login
```

**Example output:**

```text
Risk: High (score 70/100)

Why:
  - KYC update / bank account blocked: Says your bank account, card, SIM or electricity will be blocked unless you update KYC. Banks do not ask for KYC through SMS links or calls.
    matched: 'KYC', 'account will be blocked'
  - Suspicious link: Contains a shortened, look-alike or app-download (.apk) link. Don't open it.
    matched: 'http://sbi-kyc-update.xyz'
  - Urgency / pressure: Pushes you to act immediately. Scammers rush you so you don't stop and check.
    matched: 'turant'

What to do:
  - Do not click any link, call back, or reply to this message.
  - Never share an OTP, UPI PIN, CVV or password with anyone - not even someone claiming to be from your bank or the police.
  - You never need to enter a UPI PIN or scan a QR code to RECEIVE money.
  - If you already lost money, call the National Cyber Crime Helpline 1930 immediately - the faster you report, the better the chance of freezing the money.
  - Report the fraud online at https://cybercrime.gov.in and inform your bank.
  - Check with the bank, courier or company using the number on their official website or app - never the number in the message.
```

**Example input** (a made-up Hindi scam message, for illustration only):

```text
प्रिय ग्राहक, आपका SBI खाता आज बंद हो जाएगा, तुरंत केवाईसी अपडेट करें
```

**Example output** (the "What to do" list is the same as above and is shortened here):

```text
Risk: High (score 50/100)

Why:
  - KYC update / bank account blocked: Says your bank account, card, SIM or electricity will be blocked unless you update KYC. Banks do not ask for KYC through SMS links or calls.
    matched: 'केवाईसी', 'खाता आज बंद'
  - Urgency / pressure: Pushes you to act immediately. Scammers rush you so you don't stop and check.
    matched: 'तुरंत'
```

**Example input** (a normal message):

```text
Hey, are we still meeting for dinner at 8 tonight?
```

**Example output:**

```text
Risk: Low (score 0/100)

Why: no known scam pattern matched.

What to do:
  - No common scam pattern was found, but this is not a guarantee the message is safe.
  - Never share an OTP, UPI PIN or CVV with anyone.
  - If something feels wrong, call 1930 or report at https://cybercrime.gov.in.
```

## If you have been scammed

- Call the National Cyber Crime Helpline **1930** right away.
- Report at **https://cybercrime.gov.in**.
- Inform your bank and block your card / UPI if needed.
- Never share an OTP, UPI PIN, CVV or password with anyone.

## Running the tests

```bash
pip install pytest
python -m pytest
```

The tests also run automatically on GitHub Actions for every push and pull request
(Python 3.9, 3.11 and 3.13).

## Disclaimer

scam-checker is a helper, not a guarantee. It uses simple rules, so it can miss new scam
styles and can sometimes flag a genuine message. A "Low" result does not prove a message is
safe. When in doubt, don't click, don't pay, don't share any code, and verify with the official
bank or company number, or call 1930.

## Roadmap

- [x] Hindi (Devanagari) support
- [ ] More regional languages (Marathi, Tamil, Bengali, ...)
- [ ] Simple web page where you can paste a message
- [ ] More scam categories (fake investment / trading apps, electricity bill, sextortion, loan apps, fake customer care)
- [ ] Better link checks (look-alike domains)
- [x] GitHub Actions CI

## License

MIT, see [LICENSE](LICENSE).
