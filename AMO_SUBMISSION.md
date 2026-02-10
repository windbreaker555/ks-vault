# AMO Submission Guide — K's Vault
# Use this as reference when filling out the Firefox Add-ons submission form.

## Extension Name
K's Vault

## Summary (max 250 characters)
Encrypts your browser cookies at rest using AES-256-GCM. Protects your sessions from infostealer malware that dumps cookie databases. All data stays local — zero telemetry.

## Description (AMO listing page)

### Protect your sessions from cookie stealers.

Cookie-stealing malware is one of the most common attack vectors today. These tools dump your browser's cookie database from disk and steal your session tokens — giving attackers access to your accounts without needing your password.

K's Vault encrypts your cookies using AES-256-GCM and removes them from the browser's native cookie store. Attackers who dump your disk get encrypted garbage instead of usable session tokens.

**How it works:**
• Choose which sites to protect
• K's Vault encrypts your cookies and removes the originals
• On every request, cookies are decrypted in memory and injected transparently
• You browse normally — the server sees a valid session

**Security features:**
• AES-256-GCM encryption with per-cookie key derivation
• Non-extractable keys via WebCrypto API
• Emergency wipe — one click or Ctrl+Shift+K destroys all data
• Configurable failed-attempt behavior (cooldown or wipe)
• Password re-entry timeout

**Privacy:**
• No data collection, analytics, or telemetry
• No network requests — everything stays on your device
• Open source: https://github.com/windbreaker555/ks-vault

Built by Kravex — Penetration Testing & Cybersecurity
https://windbreaker555.github.io/ks-vault

## Categories
Security & Privacy

## Tags
cookies, encryption, security, privacy, session-protection, aes, infostealers

## Homepage
https://windbreaker555.github.io/ks-vault

## Support URL
https://github.com/windbreaker555/ks-vault/issues

## Privacy Policy URL
https://windbreaker555.github.io/ks-vault#privacy

---

## Permission Justifications
# (Required by Mozilla for manual review — paste these into the submission form)

### cookies
Required to read, modify, and delete cookies when the user enables protection for a domain. The extension migrates existing cookies into its encrypted store and removes the originals from the browser. When protection is removed, cookies are decrypted and restored to the browser's native store.

### webRequest
Required to intercept incoming Set-Cookie response headers and outgoing Cookie request headers. Incoming cookies are encrypted and stored locally instead of in the browser's native cookie jar. Outgoing requests have decrypted cookies injected into the Cookie header so servers receive valid sessions.

### webRequestBlocking
Required to synchronously modify HTTP headers before they reach the browser. Set-Cookie headers must be stripped before the browser processes them (to prevent plaintext storage), and Cookie headers must be injected before the request is sent.

### <all_urls>
The user can choose to protect any domain. The extension only activates interception for domains the user explicitly selects — it does not monitor or modify traffic to unprotected domains.

### storage
Used to persist the user's settings locally: protected domain list, strike mode preference, cooldown duration, and password re-entry frequency. No data is transmitted externally.

### notifications
Used to display a single notification after an emergency wipe, confirming to the user that all encrypted data has been destroyed. No other notifications are sent.

---

## Reviewer Notes
# (Optional field in AMO submission — helps the reviewer understand your code)

K's Vault is a cookie encryption extension that protects against disk-based cookie theft (infostealers). All code is unminified vanilla JavaScript with no external dependencies or build tools.

Key files:
- lib/crypto.js — WebCrypto API usage (PBKDF2, AES-256-GCM, HKDF pattern)
- lib/interceptor.js — webRequest listeners for cookie interception
- lib/storage.js — IndexedDB for encrypted blob storage
- background.js — State management, password verification, cookie migration

The extension makes zero network requests. All encryption and storage is local. No analytics, tracking, or telemetry of any kind.

Source code: https://github.com/windbreaker555/ks-vault
