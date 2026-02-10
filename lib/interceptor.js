// ============================================
// K's Vault — Interceptor Module
// webRequest hooks for cookie interception and injection
// ============================================

const KVInterceptor = (() => {

  let isActive = false;

  // ---- Start Interception ----
  // Registers webRequest listeners for protected domains

  function start(protectedDomains) {
    if (isActive) stop();
    if (!protectedDomains || protectedDomains.length === 0) return;

    // Build URL patterns for protected domains
    const patterns = protectedDomains.flatMap(domain => [
      `*://${domain}/*`,
      `*://*.${domain}/*`
    ]);

    // Intercept incoming Set-Cookie headers
    browser.webRequest.onHeadersReceived.addListener(
      onHeadersReceived,
      { urls: patterns },
      ['blocking', 'responseHeaders']
    );

    // Inject decrypted cookies into outgoing requests
    browser.webRequest.onBeforeSendHeaders.addListener(
      onBeforeSendHeaders,
      { urls: patterns },
      ['blocking', 'requestHeaders']
    );

    isActive = true;
    log('Interception started for:', protectedDomains);
  }

  // ---- Stop Interception ----

  function stop() {
    if (!isActive) return;

    browser.webRequest.onHeadersReceived.removeListener(onHeadersReceived);
    browser.webRequest.onBeforeSendHeaders.removeListener(onBeforeSendHeaders);

    isActive = false;
    log('Interception stopped.');
  }

  // ---- Incoming: Intercept Set-Cookie Headers ----
  // When a server sends Set-Cookie, we:
  // 1. Parse the cookie
  // 2. Encrypt the value
  // 3. Store the encrypted blob in IndexedDB
  // 4. Strip the Set-Cookie header so browser never stores plaintext

  function onHeadersReceived(details) {
    // Only process if vault is unlocked and has a master key
    if (!vault.isUnlocked || !vault.masterKey) {
      return {};
    }

    const url = new URL(details.url);
    const domain = url.hostname;
    const rootDomain = extractRootDomain(domain);

    // Check if this domain is protected
    if (!isDomainProtected(domain)) {
      return {};
    }

    const responseHeaders = details.responseHeaders;
    const setCookieHeaders = [];
    const filteredHeaders = [];

    for (const header of responseHeaders) {
      if (header.name.toLowerCase() === 'set-cookie') {
        setCookieHeaders.push(header.value);
      } else {
        filteredHeaders.push(header);
      }
    }

    if (setCookieHeaders.length === 0) {
      return {};
    }

    // Process each Set-Cookie header — use rootDomain for storage
    for (const setCookieStr of setCookieHeaders) {
      const parsed = parseSetCookie(setCookieStr);
      if (parsed) {
        encryptAndStore(rootDomain, domain, parsed).catch(err => {
          console.error('[K\'s Vault] Failed to encrypt cookie:', err);
        });
      }
    }

    // Return headers WITHOUT Set-Cookie — browser never stores plaintext
    return { responseHeaders: filteredHeaders };
  }

  // ---- Outgoing: Inject Decrypted Cookies ----
  // When a request goes out to a protected domain, we:
  // 1. Look up encrypted cookies for that domain
  // 2. Decrypt them
  // 3. Inject into the Cookie header

  function onBeforeSendHeaders(details) {
    if (!vault.isUnlocked || !vault.masterKey) {
      return {};
    }

    const url = new URL(details.url);
    const domain = url.hostname;

    if (!isDomainProtected(domain)) {
      return {};
    }

    const rootDomain = extractRootDomain(domain);
    return decryptAndInject(details, rootDomain);
  }

  async function decryptAndInject(details, rootDomain) {
    try {
      const cookies = await KVStorage.getAllForDomain(rootDomain);

      if (!cookies || cookies.length === 0) {
        return {};
      }

      // Decrypt all cookies for this root domain
      const decryptedPairs = [];

      for (const stored of cookies) {
        try {
          const value = await KVCrypto.decryptCookie(
            vault.masterKey,
            rootDomain,
            stored.fieldName,
            {
              ciphertext: stored.ciphertext,
              iv: stored.iv,
              timestamp: stored.timestamp
            }
          );

          // Check if cookie has expired
          if (stored.expiry && stored.expiry < Date.now()) {
            await KVStorage.deleteCookie(rootDomain, stored.fieldName, stored.cookieDomain);
            continue;
          }

          decryptedPairs.push(`${stored.fieldName}=${value}`);
        } catch (err) {
          console.warn(`[K's Vault] Failed to decrypt cookie ${stored.fieldName}:`, err);
        }
      }

      if (decryptedPairs.length === 0) {
        return {};
      }

      // Build the Cookie header
      const cookieString = decryptedPairs.join('; ');

      // Find existing Cookie header or create one
      const headers = details.requestHeaders;
      let found = false;

      for (let i = 0; i < headers.length; i++) {
        if (headers[i].name.toLowerCase() === 'cookie') {
          // Append to existing cookies (from unprotected domains/cookies)
          if (headers[i].value) {
            headers[i].value += '; ' + cookieString;
          } else {
            headers[i].value = cookieString;
          }
          found = true;
          break;
        }
      }

      if (!found) {
        headers.push({ name: 'Cookie', value: cookieString });
      }

      return { requestHeaders: headers };
    } catch (err) {
      console.error('[K\'s Vault] Injection failed:', err);
      return {};
    }
  }

  // ---- Encrypt and Store ----

  async function encryptAndStore(rootDomain, originalDomain, parsedCookie) {
    const encrypted = await KVCrypto.encryptCookie(
      vault.masterKey,
      rootDomain,
      parsedCookie.name,
      parsedCookie.value
    );

    // Calculate expiry timestamp
    let expiry = null;
    if (parsedCookie.maxAge) {
      expiry = Date.now() + (parsedCookie.maxAge * 1000);
    } else if (parsedCookie.expires) {
      expiry = new Date(parsedCookie.expires).getTime();
    }

    await KVStorage.storeCookie(rootDomain, parsedCookie.name, {
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      timestamp: encrypted.timestamp,
      expiry: expiry,
      path: parsedCookie.path || '/',
      secure: parsedCookie.secure || false,
      httpOnly: parsedCookie.httpOnly || false,
      sameSite: parsedCookie.sameSite || null,
      isSession: (!parsedCookie.maxAge && !parsedCookie.expires),
      cookieDomain: originalDomain
    });

    log(`Encrypted cookie: ${parsedCookie.name} for ${rootDomain}`);
  }

  // ---- Parse Set-Cookie Header ----
  // Extracts name, value, and attributes from a Set-Cookie string

  function parseSetCookie(str) {
    if (!str) return null;

    const parts = str.split(';').map(p => p.trim());
    const [nameValue, ...attributes] = parts;

    const eqIndex = nameValue.indexOf('=');
    if (eqIndex === -1) return null;

    const name = nameValue.substring(0, eqIndex).trim();
    const value = nameValue.substring(eqIndex + 1).trim();

    if (!name) return null;

    const cookie = {
      name: name,
      value: value,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: null,
      maxAge: null,
      expires: null
    };

    for (const attr of attributes) {
      // Clean any newlines or carriage returns from the attribute
      const cleanAttr = attr.replace(/[\r\n]/g, '').trim();
      if (!cleanAttr) continue;

      const lower = cleanAttr.toLowerCase();

      if (lower === 'secure') {
        cookie.secure = true;
      } else if (lower === 'httponly') {
        cookie.httpOnly = true;
      } else if (lower.startsWith('path=')) {
        cookie.path = cleanAttr.substring(5).trim();
      } else if (lower.startsWith('max-age=')) {
        cookie.maxAge = parseInt(cleanAttr.substring(8).trim(), 10);
      } else if (lower.startsWith('expires=')) {
        cookie.expires = cleanAttr.substring(8).trim();
      } else if (lower.startsWith('samesite=')) {
        // Only accept valid sameSite values
        const val = cleanAttr.substring(9).trim().toLowerCase();
        if (['strict', 'lax', 'none'].includes(val)) {
          cookie.sameSite = val;
        }
      }
    }

    return cookie;
  }

  // ---- Domain Matching ----
  // Checks if a domain (or its parent) is in the protected list

  function isDomainProtected(hostname) {
    for (const domain of vault.protectedDomains) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true;
      }
    }
    return false;
  }

  // ---- Root Domain Extraction ----
  // Strips subdomains to get the registrable domain.
  // www.crunchyroll.com → crunchyroll.com
  // sso.crunchyroll.com → crunchyroll.com
  // account.hackthebox.com → hackthebox.com
  // Handles common multi-part TLDs like co.uk, com.au, etc.

  const MULTI_TLDS = [
    'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in',
    'com.au', 'com.br', 'com.mx', 'com.ar', 'com.sg', 'com.tr',
    'org.uk', 'net.au', 'ac.uk', 'gov.uk', 'or.jp'
  ];

  function extractRootDomain(hostname) {
    // Remove trailing dot if present
    hostname = hostname.replace(/\.$/, '');

    const parts = hostname.split('.');

    // IP address or single label — return as-is
    if (parts.length <= 2) return hostname;

    // Check for multi-part TLDs
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_TLDS.includes(lastTwo)) {
      // e.g. www.example.co.uk → example.co.uk
      return parts.slice(-3).join('.');
    }

    // Standard: www.example.com → example.com
    return parts.slice(-2).join('.');
  }

  // ---- Public API ----

  return {
    start,
    stop,
    isActive: () => isActive,
    isDomainProtected,
    extractRootDomain
  };

})();

