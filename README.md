# K's Vault

**Encrypt your browser cookies at rest. Protect your sessions from stealers.**

K's Vault is a Firefox browser extension that encrypts your cookies using AES-256-GCM, preventing cookie-stealing malware from hijacking your sessions. Built by [Kravex](https://kravex.ro).

## The Problem

Cookie-stealing malware (infostealers) is one of the most common attack vectors today. These tools dump your browser's `cookies.sqlite` database from disk and exfiltrate session tokens to attackers — who then use them to access your accounts without needing your password.

Browser-native protections like Chrome's DPAPI or macOS Keychain are software-based. Malware running with user-level privileges can call the same decryption APIs the browser uses.

## How K's Vault Works

K's Vault moves your cookies out of the browser's native cookie store and into an encrypted vault. The browser's cookie jar stays empty for protected domains.

```
Without K's Vault:
    cookies.sqlite (plaintext) → attacker dumps → full account access

With K's Vault:
    cookies.sqlite is EMPTY for protected sites
    K's Vault IndexedDB (AES-256-GCM encrypted) → attacker dumps → useless garbage
```

**On every request**, K's Vault decrypts cookies in memory for milliseconds, injects them into the request header, and the server receives a valid session. This happens transparently — you browse normally.

## Features

- **AES-256-GCM encryption** with per-cookie key derivation (PBKDF2 + HKDF)
- **Non-extractable keys** via WebCrypto API — keys stay in protected memory
- **Selective protection** — choose which domains to protect
- **Emergency wipe** — one click or `Ctrl+Shift+K` to destroy all encrypted data
- **3-strike protection** — configurable cooldown or wipe after failed password attempts
- **Password re-entry** — configurable timeout for automatic re-locking
- **Cookie migration** — existing cookies are encrypted on protection, restored on removal
- **Domain-aware** — automatically protects all subdomains under the root domain
- **Zero telemetry** — no data ever leaves your device

## Installation

### From Firefox Add-ons (AMO)

*(Coming soon)*

### Manual / Development

1. Clone this repository
2. Open Firefox, navigate to `about:debugging#/runtime/this-firefox`
3. Click **"Load Temporary Add-on..."**
4. Select the `manifest.json` file from the cloned directory
5. The K's Vault icon appears in your toolbar

## Usage

1. **Set a master password** — this encrypts your cookies locally. Minimum 8 characters.
2. **Navigate to a site** you want to protect and log in.
3. **Click the K's Vault icon** → click **"Protect this site"**.
4. Your cookies are immediately encrypted and removed from the browser's native store.
5. Browse normally — K's Vault handles decryption and injection transparently.

> **Important:** Always log in to a site first, then enable protection. Enabling protection before logging in may interfere with the authentication flow.

### Lock / Unlock

- **Lock** stops cookie injection. Protected sites will lose their sessions until you unlock.
- Some security-conscious sites (banking, HackTheBox) may invalidate sessions server-side when they receive a cookieless request. After unlocking, you may need to re-login and re-protect these sites. This is expected and is actually the correct security behavior.

### Emergency Wipe

- Click the **Emergency Wipe** button or press `Ctrl+Shift+K`
- All encrypted cookies and vault data are permanently destroyed
- You will need to re-login to all previously protected sites

## Architecture

```
popup/              UI layer (popup, screens, domain management)
settings/           Settings page (strike mode, password change, etc.)
lib/
  crypto.js         AES-256-GCM, PBKDF2, HKDF key derivation
  storage.js        IndexedDB management for encrypted blobs
  interceptor.js    webRequest hooks for cookie interception/injection
background.js       State manager, message router, core logic
```

### Cryptographic Design

- **Master key**: Derived from password via PBKDF2 (600,000 iterations, SHA-256). Non-extractable CryptoKey — never leaves WebCrypto memory.
- **Verification hash**: Separate PBKDF2 derivation with purpose-prefixed salt (`kv:auth:`). Cryptographically independent from the encryption key.
- **Per-cookie keys**: Derived from master key via HKDF using `domain + fieldName + timestamp` as context. Each cookie has a unique encryption key.
- **Encryption**: AES-256-GCM with 96-bit random IV, 128-bit authentication tag, and Additional Authenticated Data (AAD) binding ciphertext to its domain and field name.
- **Key lifecycle**: Master key exists in memory only while the vault is unlocked. On lock, timeout, or browser close — wiped.

### Cookie Interception Flow

```
Incoming (Set-Cookie):
    Server response → webRequest.onHeadersReceived
    → Parse Set-Cookie → Encrypt value → Store in IndexedDB
    → Strip header (browser never stores plaintext)

Outgoing (Cookie):
    Browser request → webRequest.onBeforeSendHeaders
    → Read from IndexedDB → Decrypt → Inject into Cookie header
    → Server receives valid session
```

## Permissions

| Permission | Why |
|---|---|
| `cookies` | Read, modify, and delete cookies for migration and restoration |
| `webRequest` | Intercept HTTP headers to catch Set-Cookie and inject Cookie |
| `webRequestBlocking` | Modify headers synchronously before they reach the browser |
| `<all_urls>` | Operate on any domain the user chooses to protect |
| `storage` | Store vault settings (strike mode, protected domains, etc.) |
| `notifications` | Alert the user after emergency wipe |

## Threat Model

**Protects against:**
- Commodity infostealer malware that dumps cookie databases from disk
- Physical access to an unlocked machine (cookies are encrypted at rest)
- Browser profile theft / forensic extraction

**Does not protect against:**
- Kernel-level malware with live memory access (nation-state level)
- Malware that hooks browser process memory in real-time
- Compromised browser extensions with matching permissions

## Privacy

K's Vault collects no data. No analytics, no telemetry, no network requests. All encryption and storage happens locally on your device. Your master password never leaves the extension.

Full privacy policy: [windbreaker555.github.io/ks-vault](https://windbreaker555.github.io/ks-vault)

## License

MIT

## Built by

[Kravex](https://kravex.ro) — Penetration Testing & Cybersecurity
