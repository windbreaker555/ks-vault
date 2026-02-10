// ============================================
// K's Vault — Storage Module
// IndexedDB management for encrypted cookie blobs
// ============================================

const KVStorage = (() => {

  const DB_NAME = 'ks-vault';
  const DB_VERSION = 2;
  const STORE_NAME = 'cookies';

  let db = null;

  // ---- Initialize IndexedDB ----

  async function init() {
    if (db) return db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const database = event.target.result;

        // Drop old store if upgrading from v1
        if (database.objectStoreNames.contains(STORE_NAME)) {
          database.deleteObjectStore(STORE_NAME);
        }

        const store = database.createObjectStore(STORE_NAME, {
          keyPath: 'id'
        });
        // Index by root domain for fast lookups
        store.createIndex('domain', 'domain', { unique: false });
      };

      request.onsuccess = (event) => {
        db = event.target.result;
        log('IndexedDB initialized.');
        resolve(db);
      };

      request.onerror = (event) => {
        console.error('[K\'s Vault] IndexedDB error:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  // ---- Ensure DB is ready ----

  async function getDB() {
    if (!db) await init();
    return db;
  }

  // ---- Store Encrypted Cookie ----

  async function storeCookie(domain, fieldName, data) {
    const database = await getDB();

    // Include cookieDomain in key to prevent collisions across subdomains
    const cookieDomain = data.cookieDomain || domain;
    const id = `${domain}:${cookieDomain}:${fieldName}`;

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);

      const record = {
        id: id,
        domain: domain,
        fieldName: fieldName,
        cookieDomain: cookieDomain,
        ciphertext: data.ciphertext,
        iv: data.iv,
        timestamp: data.timestamp,
        expiry: data.expiry || null,
        path: data.path || '/',
        secure: data.secure || false,
        httpOnly: data.httpOnly || false,
        sameSite: data.sameSite || null,
        isSession: data.isSession || false,
        storedAt: Date.now()
      };

      const request = store.put(record);

      request.onsuccess = () => resolve(true);
      request.onerror = (event) => {
        console.error('[K\'s Vault] Store failed:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  // ---- Get Single Cookie ----

  async function getCookie(domain, fieldName, cookieDomain) {
    const database = await getDB();
    const cd = cookieDomain || domain;
    const id = `${domain}:${cd}:${fieldName}`;

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(id);

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Get All Cookies for Domain ----

  async function getAllForDomain(domain) {
    const database = await getDB();

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const index = store.index('domain');
      const request = index.getAll(domain);

      request.onsuccess = () => resolve(request.result || []);
      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Delete Single Cookie ----

  async function deleteCookie(domain, fieldName, cookieDomain) {
    const database = await getDB();
    const cd = cookieDomain || domain;
    const id = `${domain}:${cd}:${fieldName}`;

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(id);

      request.onsuccess = () => resolve(true);
      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Delete All Cookies for Domain ----

  async function deleteAllForDomain(domain) {
    const database = await getDB();

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const index = store.index('domain');
      const request = index.openCursor(domain);

      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        } else {
          resolve(true);
        }
      };

      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Wipe Everything ----

  async function wipeAll() {
    const database = await getDB();

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        log('All encrypted cookies wiped.');
        resolve(true);
      };
      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Count Cookies ----

  async function count() {
    const database = await getDB();

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.count();

      request.onsuccess = () => resolve(request.result);
      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Clear Session Cookies ----
  // Called on browser startup to remove cookies that had no expiry

  async function clearSessionCookies() {
    const database = await getDB();

    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.openCursor();
      let cleared = 0;

      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          if (cursor.value.isSession) {
            cursor.delete();
            cleared++;
          }
          cursor.continue();
        } else {
          log(`Cleared ${cleared} session cookies.`);
          resolve(cleared);
        }
      };

      request.onerror = (event) => reject(event.target.error);
    });
  }

  // ---- Public API ----

  return {
    init,
    storeCookie,
    getCookie,
    getAllForDomain,
    deleteCookie,
    deleteAllForDomain,
    wipeAll,
    count,
    clearSessionCookies
  };

})();

