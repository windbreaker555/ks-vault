# K's Vault — Privacy Policy

**Last updated:** February 2025

## Overview

K's Vault is a browser extension developed by Kravex that encrypts browser cookies locally on your device. This privacy policy explains what data K's Vault handles and how it is processed.

## Data Collection

**K's Vault collects no data.** Specifically:

- No personal information is collected
- No usage analytics or telemetry
- No cookies or browsing data are transmitted to any server
- No network requests are made by the extension
- No third-party services or SDKs are integrated

## Data Processing

All data processing occurs entirely on your device:

- **Master password**: Used to derive encryption keys via PBKDF2. The password itself is never stored — only a verification hash derived from it. The hash cannot be reversed to recover the password.
- **Encrypted cookies**: Cookie values are encrypted using AES-256-GCM and stored in the extension's local IndexedDB. Encrypted data never leaves your device.
- **Settings**: Preferences such as protected domains, strike mode, and re-entry frequency are stored locally using the browser's extension storage API.

## Data Storage

All data is stored locally using:

- **IndexedDB**: Encrypted cookie blobs (ciphertext, initialization vectors, timestamps)
- **Browser extension storage**: Vault configuration and settings

No data is stored on external servers, cloud services, or any location outside your browser profile.

## Data Deletion

- **Emergency Wipe**: Permanently deletes all encrypted cookies, settings, and vault data from your device.
- **Remove Protection**: Decrypts and restores cookies to the browser's native store, then removes them from K's Vault's storage.
- **Uninstalling**: Removing the extension deletes all associated IndexedDB and extension storage data.

## Permissions

K's Vault requests the following browser permissions, used exclusively for local cookie encryption:

- **cookies**: To read, encrypt, and manage cookies for domains you choose to protect
- **webRequest / webRequestBlocking**: To intercept and modify HTTP cookie headers locally
- **all_urls**: To operate on any domain you choose to protect
- **storage**: To save your settings locally
- **notifications**: To alert you after an emergency wipe

No permission is used to transmit data externally.

## Third Parties

K's Vault does not integrate with, transmit data to, or receive data from any third-party services.

## Changes

If this privacy policy is updated, the changes will be published at [windbreaker555.github.io/ks-vault](https://windbreaker555.github.io/ks-vault) and noted in the extension's changelog.

## Contact

For questions about this privacy policy or K's Vault:

- Website: [kravex.ro](https://kravex.ro)
- Email: contact@kravex.ro
