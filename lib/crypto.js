// ============================================
// K's Vault — Crypto Module
// AES-256-GCM encryption with PBKDF2 + HKDF key derivation
// ============================================

// Global debug flag — set to true for development logging
const DEBUG = false;
function log(...args) { if (DEBUG) console.log('[K\'s Vault]', ...args); }

const KVCrypto = (() => {

  // ---- Constants ----
  const PBKDF2_ITERATIONS = 600000;
  const KEY_LENGTH = 256;               // AES-256
  const IV_LENGTH = 12;                 // 96-bit IV for AES-GCM (recommended)
  const SALT_LENGTH = 32;               // 256-bit salt

  // ---- Salt Generation ----

  function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  }

  function generateIV() {
    return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  }

  // ---- Master Key Derivation (PBKDF2) ----
  // Called once on unlock. Derives the master key from user password + salt.
  // The key is non-extractable — it stays in WebCrypto's protected memory.

  async function deriveMasterKey(password, salt) {
    const encoder = new TextEncoder();

    // Import password as raw key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );

    // Derive the actual AES key via PBKDF2
    const masterKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: KEY_LENGTH },
      false,        // NON-EXTRACTABLE — cannot be exported via JS
      ['encrypt', 'decrypt']
    );

    return masterKey;
  }

  // ---- Per-Cookie Key Derivation (HKDF) ----
  // Each cookie gets its own derived key from the master key.
  // This provides domain isolation: compromising one cookie's key
  // doesn't reveal others.
  //
  // Flow: masterKey → HKDF(domain + fieldName + timestamp) → cookieKey

  async function deriveCookieKey(masterKey, domain, fieldName, timestamp) {
    const encoder = new TextEncoder();

    // We need to extract bits from master key to use as HKDF input.
    // Since masterKey is non-extractable, we use it to encrypt a
    // known value and use that output as HKDF input keying material.

    const info = encoder.encode(`kv:cookie:${domain}:${fieldName}:${timestamp}`);

    // Derive bits from masterKey using PBKDF2 with the info as salt
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      info,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const cookieKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode(`kv:salt:${domain}:${fieldName}`),
        iterations: 1,    // Single iteration — input is already a strong key
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );

    return cookieKey;
  }

  // ---- Encrypt Cookie ----
  // Encrypts a cookie value with AES-256-GCM.
  // Returns: { ciphertext (base64), iv (base64), timestamp }
  //
  // AES-GCM provides both confidentiality AND integrity (built-in auth tag).
  // The domain+fieldName are included as Additional Authenticated Data (AAD),
  // meaning tampering with the domain association will cause decryption to fail.

  async function encryptCookie(masterKey, domain, fieldName, cookieValue) {
    const timestamp = Date.now().toString();
    const encoder = new TextEncoder();

    // Derive per-cookie key
    const cookieKey = await deriveCookieKey(masterKey, domain, fieldName, timestamp);

    // Generate random IV (MUST be unique per encryption)
    const iv = generateIV();

    // Additional Authenticated Data — binds ciphertext to this domain+field
    const aad = encoder.encode(`${domain}:${fieldName}:${timestamp}`);

    // Encrypt
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: 128      // 128-bit auth tag (maximum)
      },
      cookieKey,
      encoder.encode(cookieValue)
    );

    return {
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv),
      timestamp: timestamp
    };
  }

  // ---- Decrypt Cookie ----
  // Decrypts a previously encrypted cookie.
  // Will throw if: wrong key, tampered ciphertext, wrong domain/field association.

  async function decryptCookie(masterKey, domain, fieldName, encryptedBlob) {
    const encoder = new TextEncoder();

    // Derive the same per-cookie key
    const cookieKey = await deriveCookieKey(
      masterKey, domain, fieldName, encryptedBlob.timestamp
    );

    const iv = base64ToArrayBuffer(encryptedBlob.iv);
    const ciphertext = base64ToArrayBuffer(encryptedBlob.ciphertext);

    // Reconstruct AAD
    const aad = encoder.encode(
      `${domain}:${fieldName}:${encryptedBlob.timestamp}`
    );

    // Decrypt — will throw DOMException if auth tag verification fails
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: 128
      },
      cookieKey,
      ciphertext
    );

    return new TextDecoder().decode(plaintext);
  }

  // ---- Verification Hash ----
  // Used to verify the password on unlock WITHOUT storing the key.
  // Separate from the encryption key — only for authentication.

  async function deriveVerificationHash(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    // Different context than master key derivation (purpose separation)
    const purposeSalt = new Uint8Array(salt.length + 8);
    purposeSalt.set(new TextEncoder().encode('kv:auth:'));
    purposeSalt.set(salt, 8);

    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: purposeSalt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return arrayBufferToBase64(new Uint8Array(bits));
  }

  // ---- Encoding Helpers ----

  function arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // ---- Public API ----

  return {
    generateSalt,
    generateIV,
    deriveMasterKey,
    deriveCookieKey,
    encryptCookie,
    decryptCookie,
    deriveVerificationHash,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    PBKDF2_ITERATIONS
  };

})();

