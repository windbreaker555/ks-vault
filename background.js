// ============================================
// K's Vault — Background Script
// Central state manager and message router
// ============================================

const vault = {
  isSetup: false,
  isUnlocked: false,
  masterKey: null,             // CryptoKey in memory (non-extractable) — only while unlocked
  masterKeyHash: null,         // stored hash to verify password
  salt: null,                  // stored salt for PBKDF2
  protectedDomains: [],        // list of domains user chose to protect
  attempts: 0,
  maxAttempts: 3,
  strikeMode: 'cooldown',     // 'cooldown' or 'wipe'
  cooldownSeconds: 900,        // 15 minutes
  cooldownUntil: null,
  reentryMinutes: 0,           // 0 = only on browser start
  lastUnlock: null
};

// ---- Initialization ----

async function initVault() {
  // Initialize IndexedDB
  await KVStorage.init();

  const stored = await browser.storage.local.get([
    'vaultSetup',
    'masterKeyHash',
    'salt',
    'protectedDomains',
    'strikeMode',
    'cooldownSeconds',
    'reentryMinutes'
  ]);

  if (stored.vaultSetup) {
    vault.isSetup = true;
    vault.masterKeyHash = stored.masterKeyHash;
    vault.salt = stored.salt;
    vault.protectedDomains = stored.protectedDomains || [];
    vault.strikeMode = stored.strikeMode || 'cooldown';
    vault.cooldownSeconds = stored.cooldownSeconds || 900;
    vault.reentryMinutes = stored.reentryMinutes || 0;

    // Clear session cookies from previous browser session
    await KVStorage.clearSessionCookies();
  }
}

// ---- State Snapshot (sent to popup) ----

function getState() {
  const now = Date.now();
  const isCooldown = vault.cooldownUntil && now < vault.cooldownUntil;
  const cooldownRemaining = isCooldown
    ? Math.ceil((vault.cooldownUntil - now) / 1000)
    : 0;

  // Check re-entry timeout
  if (vault.isUnlocked && vault.reentryMinutes > 0 && vault.lastUnlock) {
    const elapsed = (now - vault.lastUnlock) / 1000 / 60;
    if (elapsed >= vault.reentryMinutes) {
      vault.isUnlocked = false;
      vault.masterKey = null;    // Wipe key on timeout
      KVInterceptor.stop();      // Stop intercepting on timeout
    }
  }

  return {
    isSetup: vault.isSetup,
    isUnlocked: vault.isUnlocked,
    isCooldown: isCooldown,
    cooldownRemaining: cooldownRemaining,
    attemptsRemaining: vault.maxAttempts - vault.attempts,
    protectedDomains: vault.protectedDomains.length,
    protectedDomainsList: vault.protectedDomains
  };
}

// Returns state with async data (encrypted cookie count)
async function getFullState() {
  const state = getState();
  try {
    state.encryptedCookies = await KVStorage.count();
  } catch (e) {
    state.encryptedCookies = 0;
  }
  return state;
}

// ---- Setup ----

async function handleSetup(password) {
  try {
    // Generate random salt
    const salt = KVCrypto.generateSalt();
    const saltB64 = KVCrypto.arrayBufferToBase64(salt);

    // Derive verification hash (for password checking on unlock)
    const keyHash = await KVCrypto.deriveVerificationHash(password, salt);

    // Derive the actual master encryption key (stays in memory)
    const masterKey = await KVCrypto.deriveMasterKey(password, salt);

    // Store setup data
    await browser.storage.local.set({
      vaultSetup: true,
      masterKeyHash: keyHash,
      salt: saltB64,
      protectedDomains: [],
      strikeMode: 'cooldown',
      reentryMinutes: 0
    });

    vault.isSetup = true;
    vault.isUnlocked = true;
    vault.masterKey = masterKey;
    vault.masterKeyHash = keyHash;
    vault.salt = saltB64;
    vault.attempts = 0;
    vault.lastUnlock = Date.now();

    // Start intercepting cookies for protected domains
    KVInterceptor.start(vault.protectedDomains);

    return { success: true, state: getState() };
  } catch (e) {
    console.error('[K\'s Vault] Setup failed:', e);
    return { success: false, error: 'Setup failed. Please try again.' };
  }
}

// ---- Unlock ----

async function handleUnlock(password) {
  // Check cooldown
  if (vault.cooldownUntil && Date.now() < vault.cooldownUntil) {
    const remaining = Math.ceil((vault.cooldownUntil - Date.now()) / 1000);
    return { success: false, cooldown: true, cooldownRemaining: remaining };
  }

  // Verify password
  const salt = KVCrypto.base64ToArrayBuffer(vault.salt);
  const hash = await KVCrypto.deriveVerificationHash(password, salt);

  if (hash !== vault.masterKeyHash) {
    vault.attempts++;
    const remaining = vault.maxAttempts - vault.attempts;

    if (remaining <= 0) {
      if (vault.strikeMode === 'wipe') {
        await handlePanicWipe();
        return { success: false, wiped: true };
      } else {
        // Cooldown mode
        vault.cooldownUntil = Date.now() + (vault.cooldownSeconds * 1000);
        vault.attempts = 0;
        const cooldownRemaining = vault.cooldownSeconds;
        return { success: false, cooldown: true, cooldownRemaining };
      }
    }

    return {
      success: false,
      error: 'Wrong password.',
      attemptsRemaining: remaining
    };
  }

  // Success — derive master key and hold in memory
  const masterKey = await KVCrypto.deriveMasterKey(password, salt);

  vault.isUnlocked = true;
  vault.masterKey = masterKey;
  vault.attempts = 0;
  vault.cooldownUntil = null;
  vault.lastUnlock = Date.now();

  // Start intercepting cookies
  KVInterceptor.start(vault.protectedDomains);

  return { success: true, state: getState() };
}

// ---- Lock ----

function handleLock() {
  vault.isUnlocked = false;
  vault.masterKey = null;      // Wipe key from memory
  vault.attempts = 0;
  KVInterceptor.stop();        // Stop intercepting
  return { success: true };
}

// ---- Domain Management ----

async function handleToggleDomain(domain, protect) {
  // Extract root domain so www.crunchyroll.com → crunchyroll.com
  const rootDomain = KVInterceptor.extractRootDomain(domain);

  if (protect && !vault.protectedDomains.includes(rootDomain)) {
    vault.protectedDomains.push(rootDomain);

    // MIGRATE existing cookies: grab from root + all subdomains
    if (vault.isUnlocked && vault.masterKey) {
      await migrateExistingCookies(rootDomain);
    }
  } else if (!protect) {
    // RESTORE cookies before removing protection
    if (vault.isUnlocked && vault.masterKey) {
      await restoreCookies(rootDomain);
    }
    vault.protectedDomains = vault.protectedDomains.filter(d => d !== rootDomain);
    await KVStorage.deleteAllForDomain(rootDomain);
  }

  await browser.storage.local.set({
    protectedDomains: vault.protectedDomains
  });

  // Restart interception with updated domain list
  if (vault.isUnlocked) {
    KVInterceptor.start(vault.protectedDomains);
  }

  return { success: true, state: getState() };
}

// ---- Cookie Migration ----
// When protecting a domain, grab all existing cookies, encrypt them,
// store in IndexedDB, and delete originals from browser.

async function migrateExistingCookies(rootDomain) {
  try {
    // getAll with root domain returns cookies from ALL subdomains too
    const cookies = await browser.cookies.getAll({ domain: rootDomain });
    let migrated = 0;

    for (const cookie of cookies) {
      // Use rootDomain as storage key, preserve original cookie domain for restoration
      const encrypted = await KVCrypto.encryptCookie(
        vault.masterKey,
        rootDomain,
        cookie.name,
        cookie.value
      );

      let expiry = null;
      if (cookie.expirationDate) {
        expiry = cookie.expirationDate * 1000;
      }

      await KVStorage.storeCookie(rootDomain, cookie.name, {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        timestamp: encrypted.timestamp,
        expiry: expiry,
        path: cookie.path || '/',
        secure: cookie.secure || false,
        httpOnly: cookie.httpOnly || false,
        sameSite: cookie.sameSite || null,
        isSession: cookie.session || false,
        cookieDomain: cookie.domain   // preserve original for restoration
      });

      // Delete original from browser
      const protocol = cookie.secure ? 'https' : 'http';
      const cookieDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
      await browser.cookies.remove({
        url: `${protocol}://${cookieDomain}${cookie.path}`,
        name: cookie.name
      });

      migrated++;
    }

    log(`Migrated ${migrated} existing cookies for ${rootDomain}`);
  } catch (err) {
    console.error(`[K's Vault] Migration failed for ${rootDomain}:`, err);
  }
}

// ---- Cookie Restoration ----
// When removing protection, decrypt cookies and put them back in the browser.

async function restoreCookies(domain) {
  try {
    const storedCookies = await KVStorage.getAllForDomain(domain);
    let restored = 0;

    for (const stored of storedCookies) {
      try {
        const value = await KVCrypto.decryptCookie(
          vault.masterKey,
          domain,
          stored.fieldName,
          {
            ciphertext: stored.ciphertext,
            iv: stored.iv,
            timestamp: stored.timestamp
          }
        );

        // Use preserved original cookie domain, fallback to root domain
        const cookieDomain = stored.cookieDomain || domain;
        const cleanDomain = cookieDomain.startsWith('.') ? cookieDomain.substring(1) : cookieDomain;

        const cookieDetails = {
          url: `https://${cleanDomain}${stored.path || '/'}`,
          name: stored.fieldName,
          value: value,
          path: stored.path || '/',
          secure: stored.secure || false,
          httpOnly: stored.httpOnly || false
        };

        if (stored.expiry) {
          cookieDetails.expirationDate = stored.expiry / 1000;
        }

        // Only set sameSite if it's a valid value
        if (stored.sameSite && ['strict', 'lax', 'none'].includes(stored.sameSite.toLowerCase())) {
          cookieDetails.sameSite = stored.sameSite.toLowerCase();
        }

        await browser.cookies.set(cookieDetails);
        restored++;
      } catch (err) {
        console.warn(`[K's Vault] Failed to restore cookie ${stored.fieldName}:`, err);
      }
    }

    log(`Restored ${restored} cookies for ${domain}`);
  } catch (err) {
    console.error(`[K's Vault] Restoration failed for ${domain}:`, err);
  }
}

// ---- Panic Wipe ----

async function handlePanicWipe() {
  // Stop interception immediately
  KVInterceptor.stop();

  // Wipe all encrypted cookie data from IndexedDB
  await KVStorage.wipeAll();

  // Delete all browser cookies for protected domains
  for (const domain of vault.protectedDomains) {
    const cookies = await browser.cookies.getAll({ domain });
    for (const cookie of cookies) {
      await browser.cookies.remove({
        url: `https://${cookie.domain}${cookie.path}`,
        name: cookie.name
      });
    }
  }

  // Reset vault state
  await browser.storage.local.clear();

  vault.isSetup = false;
  vault.isUnlocked = false;
  vault.masterKey = null;        // Wipe key from memory
  vault.masterKeyHash = null;
  vault.salt = null;
  vault.protectedDomains = [];
  vault.attempts = 0;
  vault.cooldownUntil = null;

  // Send notification
  browser.notifications.create('vault-wiped', {
    type: 'basic',
    title: 'K\'s Vault',
    message: 'Emergency wipe complete. All protected data has been destroyed.'
  });

  return { success: true };
}

// ---- Settings ----

function getSettings() {
  return {
    strikeMode: vault.strikeMode,
    cooldownSeconds: vault.cooldownSeconds,
    reentryMinutes: vault.reentryMinutes
  };
}

async function handleUpdateSetting(key, value) {
  // Only allow known settings
  const allowed = ['strikeMode', 'cooldownSeconds', 'reentryMinutes'];
  if (!allowed.includes(key)) return { success: false, error: 'Unknown setting.' };

  vault[key] = value;
  await browser.storage.local.set({ [key]: value });

  return { success: true };
}

async function handleChangePassword(currentPassword, newPassword) {
  // Verify current password
  const salt = KVCrypto.base64ToArrayBuffer(vault.salt);
  const hash = await KVCrypto.deriveVerificationHash(currentPassword, salt);

  if (hash !== vault.masterKeyHash) {
    return { success: false, error: 'Current password is incorrect.' };
  }

  try {
    // Generate new salt
    const newSalt = KVCrypto.generateSalt();
    const newSaltB64 = KVCrypto.arrayBufferToBase64(newSalt);

    // Derive new verification hash
    const newHash = await KVCrypto.deriveVerificationHash(newPassword, newSalt);

    // Derive new master key
    const newMasterKey = await KVCrypto.deriveMasterKey(newPassword, newSalt);

    // Re-encrypt all stored cookies with new key
    const oldMasterKey = vault.masterKey;
    const allDomains = vault.protectedDomains;

    for (const domain of allDomains) {
      const cookies = await KVStorage.getAllForDomain(domain);

      for (const stored of cookies) {
        try {
          // Decrypt with old key
          const plainValue = await KVCrypto.decryptCookie(
            oldMasterKey,
            domain,
            stored.fieldName,
            {
              ciphertext: stored.ciphertext,
              iv: stored.iv,
              timestamp: stored.timestamp
            }
          );

          // Re-encrypt with new key
          const encrypted = await KVCrypto.encryptCookie(
            newMasterKey,
            domain,
            stored.fieldName,
            plainValue
          );

          // Update stored record
          await KVStorage.storeCookie(domain, stored.fieldName, {
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            timestamp: encrypted.timestamp,
            expiry: stored.expiry,
            path: stored.path,
            secure: stored.secure,
            httpOnly: stored.httpOnly,
            sameSite: stored.sameSite,
            isSession: stored.isSession
          });
        } catch (err) {
          console.warn(`[K's Vault] Failed to re-encrypt ${stored.fieldName}:`, err);
        }
      }
    }

    // Update vault state
    vault.masterKeyHash = newHash;
    vault.salt = newSaltB64;
    vault.masterKey = newMasterKey;

    // Persist
    await browser.storage.local.set({
      masterKeyHash: newHash,
      salt: newSaltB64
    });

    log('Password changed successfully.');
    return { success: true };
  } catch (err) {
    console.error('[K\'s Vault] Password change failed:', err);
    return { success: false, error: 'Password change failed. Please try again.' };
  }
}

// ---- Message Router ----

browser.runtime.onMessage.addListener((message, sender) => {
  switch (message.action) {
    case 'getState':
      return Promise.resolve(getState());

    case 'getFullState':
      return getFullState();

    case 'getSettings':
      return Promise.resolve(getSettings());

    case 'setup':
      return handleSetup(message.password);

    case 'unlock':
      return handleUnlock(message.password);

    case 'lock':
      return Promise.resolve(handleLock());

    case 'toggleDomain':
      return handleToggleDomain(message.domain, message.protect);

    case 'updateSetting':
      return handleUpdateSetting(message.key, message.value);

    case 'changePassword':
      return handleChangePassword(message.currentPassword, message.newPassword);

    case 'panicWipe':
      return handlePanicWipe();

    default:
      return Promise.resolve({ error: 'Unknown action' });
  }
});

// ---- Keyboard Shortcut (Panic Wipe) ----

browser.commands.onCommand.addListener((command) => {
  if (command === 'panic-wipe') {
    handlePanicWipe();
  }
});

// ---- Start ----

initVault();
