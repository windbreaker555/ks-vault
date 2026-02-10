// ============================================
// K's Vault — Popup Controller
// ============================================

const screens = {
  setup: document.getElementById('screen-setup'),
  unlock: document.getElementById('screen-unlock'),
  cooldown: document.getElementById('screen-cooldown'),
  dashboard: document.getElementById('screen-dashboard')
};

// ---- Screen Management ----

function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.add('hidden'));
  screens[name].classList.remove('hidden');
}

// ---- Initialize ----

async function init() {
  const state = await browser.runtime.sendMessage({ action: 'getState' });

  if (!state.isSetup) {
    showScreen('setup');
  } else if (state.isCooldown) {
    showScreen('cooldown');
    startCooldownTimer(state.cooldownRemaining);
  } else if (!state.isUnlocked) {
    showScreen('unlock');
    updateAttempts(state.attemptsRemaining);
  } else {
    showScreen('dashboard');
    // Get full state with encrypted cookie count
    const fullState = await browser.runtime.sendMessage({ action: 'getFullState' });
    updateDashboard(fullState);
  }
}

// ---- Setup Flow ----

document.getElementById('btn-setup').addEventListener('click', async () => {
  const password = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm').value;
  const errorEl = document.getElementById('setup-error');

  errorEl.classList.add('hidden');

  if (password.length < 8) {
    errorEl.textContent = 'Password must be at least 8 characters.';
    errorEl.classList.remove('hidden');
    return;
  }

  if (password !== confirm) {
    errorEl.textContent = 'Passwords do not match.';
    errorEl.classList.remove('hidden');
    return;
  }

  const result = await browser.runtime.sendMessage({
    action: 'setup',
    password: password
  });

  if (result.success) {
    showScreen('dashboard');
    const fullState = await browser.runtime.sendMessage({ action: 'getFullState' });
    updateDashboard(fullState);
  } else {
    errorEl.textContent = result.error || 'Setup failed.';
    errorEl.classList.remove('hidden');
  }
});

// Allow Enter key on setup fields
['setup-password', 'setup-confirm'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('btn-setup').click();
  });
});

// ---- Unlock Flow ----

document.getElementById('btn-unlock').addEventListener('click', async () => {
  const password = document.getElementById('unlock-password').value;
  const errorEl = document.getElementById('unlock-error');

  errorEl.classList.add('hidden');

  if (!password) return;

  const result = await browser.runtime.sendMessage({
    action: 'unlock',
    password: password
  });

  if (result.success) {
    showScreen('dashboard');
    const fullState = await browser.runtime.sendMessage({ action: 'getFullState' });
    updateDashboard(fullState);
  } else if (result.cooldown) {
    showScreen('cooldown');
    startCooldownTimer(result.cooldownRemaining);
  } else if (result.wiped) {
    // 3-strike wipe happened
    showScreen('setup');
    showWipeNotification();
  } else {
    errorEl.textContent = result.error || 'Wrong password.';
    errorEl.classList.remove('hidden');
    updateAttempts(result.attemptsRemaining);
  }

  // Clear the input
  document.getElementById('unlock-password').value = '';
});

document.getElementById('unlock-password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-unlock').click();
});

function updateAttempts(remaining) {
  const el = document.getElementById('unlock-attempts');
  const countEl = document.getElementById('attempts-remaining');

  if (remaining < 3) {
    countEl.textContent = remaining;
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
}

// ---- Cooldown Timer ----

let cooldownInterval = null;

function startCooldownTimer(secondsRemaining) {
  const timerEl = document.getElementById('cooldown-time');

  clearInterval(cooldownInterval);

  function updateDisplay() {
    const mins = Math.floor(secondsRemaining / 60);
    const secs = secondsRemaining % 60;
    timerEl.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }

  updateDisplay();

  cooldownInterval = setInterval(() => {
    secondsRemaining--;

    if (secondsRemaining <= 0) {
      clearInterval(cooldownInterval);
      showScreen('unlock');
      updateAttempts(3);
      return;
    }

    updateDisplay();
  }, 1000);
}

// ---- Dashboard ----

function updateDashboard(state) {
  document.getElementById('protected-count').textContent = state.protectedDomains || 0;
  document.getElementById('encrypted-count').textContent = state.encryptedCookies || 0;

  // Get current tab domain
  browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
    if (tabs[0] && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        const domainEl = document.getElementById('current-domain-name');
        const btnEl = document.getElementById('btn-toggle-domain');
        const sectionEl = document.getElementById('current-domain-section');
        const hintEl = document.getElementById('protect-hint');

        // Don't show for internal pages
        if (url.protocol === 'about:' || url.protocol === 'moz-extension:') {
          sectionEl.classList.add('hidden');
          hintEl.classList.add('hidden');
          return;
        }

        // Use root domain for display and protection
        const rootDomain = extractRootDomain(domain);
        sectionEl.classList.remove('hidden');
        domainEl.textContent = rootDomain;

        const isProtected = state.protectedDomainsList &&
          state.protectedDomainsList.includes(rootDomain);

        if (isProtected) {
          btnEl.textContent = 'Remove protection';
          btnEl.classList.add('active');
          hintEl.classList.add('hidden');
        } else {
          btnEl.textContent = 'Protect this site';
          btnEl.classList.remove('active');
          hintEl.classList.remove('hidden');
        }

        btnEl.onclick = () => toggleDomainProtection(rootDomain, !isProtected);
      } catch (e) {
        document.getElementById('current-domain-section').classList.add('hidden');
      }
    }
  });
}

async function toggleDomainProtection(domain, protect) {
  const result = await browser.runtime.sendMessage({
    action: 'toggleDomain',
    domain: domain,
    protect: protect
  });

  if (result.success) {
    // Get full state to update encrypted count
    const fullState = await browser.runtime.sendMessage({ action: 'getFullState' });
    updateDashboard(fullState);
  }
}

// ---- Panic Wipe ----

document.getElementById('btn-panic').addEventListener('click', () => {
  showModal(
    'This will permanently delete all encrypted cookies and lock the vault. You will need to re-login to all protected sites. Continue?',
    async () => {
      await browser.runtime.sendMessage({ action: 'panicWipe' });
      showScreen('setup');
    }
  );
});

// ---- Lock ----

document.getElementById('btn-lock').addEventListener('click', async () => {
  await browser.runtime.sendMessage({ action: 'lock' });
  showScreen('unlock');
  updateAttempts(3);
});

// ---- Settings ----

document.getElementById('btn-settings').addEventListener('click', () => {
  browser.runtime.openOptionsPage();
});

// ---- Modal ----

function showModal(message, onConfirm) {
  const modal = document.getElementById('modal-confirm');
  document.getElementById('modal-message').textContent = message;
  modal.classList.remove('hidden');

  document.getElementById('modal-cancel').onclick = () => {
    modal.classList.add('hidden');
  };

  document.getElementById('modal-confirm-btn').onclick = () => {
    modal.classList.add('hidden');
    onConfirm();
  };
}

// ---- Wipe Notification ----

function showWipeNotification() {
  const errorEl = document.getElementById('setup-error') ||
    document.querySelector('.error');
  // Reuse setup screen to show what happened
  const hint = document.querySelector('#screen-setup .hint');
  if (hint) {
    hint.textContent = 'Vault was wiped after too many failed attempts. Set a new password to start fresh.';
    hint.style.color = '#C45B5B';
  }
}

// ---- Root Domain Extraction ----

const MULTI_TLDS = [
  'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in',
  'com.au', 'com.br', 'com.mx', 'com.ar', 'com.sg', 'com.tr',
  'org.uk', 'net.au', 'ac.uk', 'gov.uk', 'or.jp'
];

function extractRootDomain(hostname) {
  hostname = hostname.replace(/\.$/, '');
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_TLDS.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// ---- Start ----

init();
