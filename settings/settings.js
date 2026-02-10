// ============================================
// K's Vault — Settings Controller
// ============================================

// ---- Initialize ----

async function init() {
  const state = await browser.runtime.sendMessage({ action: 'getState' });

  if (!state.isUnlocked) {
    document.getElementById('locked-notice').classList.remove('hidden');
    document.getElementById('settings-content').classList.add('hidden');
    return;
  }

  document.getElementById('locked-notice').classList.add('hidden');
  document.getElementById('settings-content').classList.remove('hidden');

  // Load current settings
  const settings = await browser.runtime.sendMessage({ action: 'getSettings' });
  applySettings(settings);
  renderDomains(state.protectedDomainsList || []);
}

function applySettings(settings) {
  // Strike mode
  const cooldownBtn = document.getElementById('mode-cooldown');
  const wipeBtn = document.getElementById('mode-wipe');
  const cooldownSetting = document.getElementById('cooldown-setting');

  if (settings.strikeMode === 'wipe') {
    cooldownBtn.classList.remove('active');
    wipeBtn.classList.add('active');
    cooldownSetting.classList.add('hidden');
  } else {
    cooldownBtn.classList.add('active');
    wipeBtn.classList.remove('active');
    cooldownSetting.classList.remove('hidden');
  }

  // Cooldown duration
  document.getElementById('cooldown-duration').value = settings.cooldownSeconds || 900;

  // Re-entry frequency
  document.getElementById('reentry-frequency').value = settings.reentryMinutes || 0;
}

// ---- Strike Mode Toggle ----

document.getElementById('mode-cooldown').addEventListener('click', () => {
  document.getElementById('mode-cooldown').classList.add('active');
  document.getElementById('mode-wipe').classList.remove('active');
  document.getElementById('cooldown-setting').classList.remove('hidden');
  saveSetting('strikeMode', 'cooldown');
});

document.getElementById('mode-wipe').addEventListener('click', () => {
  showModal(
    'Wipe mode will permanently delete all encrypted data after 3 failed attempts. Are you sure?',
    () => {
      document.getElementById('mode-wipe').classList.add('active');
      document.getElementById('mode-cooldown').classList.remove('active');
      document.getElementById('cooldown-setting').classList.add('hidden');
      saveSetting('strikeMode', 'wipe');
    }
  );
});

// ---- Cooldown Duration ----

document.getElementById('cooldown-duration').addEventListener('change', (e) => {
  saveSetting('cooldownSeconds', parseInt(e.target.value, 10));
});

// ---- Re-entry Frequency ----

document.getElementById('reentry-frequency').addEventListener('change', (e) => {
  saveSetting('reentryMinutes', parseInt(e.target.value, 10));
});

// ---- Save Setting ----

async function saveSetting(key, value) {
  await browser.runtime.sendMessage({
    action: 'updateSetting',
    key: key,
    value: value
  });
}

// ---- Protected Domains ----

function renderDomains(domains) {
  const container = document.getElementById('domains-list');

  if (!domains || domains.length === 0) {
    container.innerHTML = '<p class="empty-state">No domains protected yet.</p>';
    return;
  }

  container.innerHTML = domains.map(domain => `
    <div class="domain-item">
      <span class="domain-item-name">${domain}</span>
      <button class="domain-item-remove" data-domain="${domain}" title="Remove protection">✕</button>
    </div>
  `).join('');

  // Attach remove handlers
  container.querySelectorAll('.domain-item-remove').forEach(btn => {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain;
      showModal(
        `Remove protection from ${domain}? Cookies will be decrypted and restored to the browser.`,
        async () => {
          const result = await browser.runtime.sendMessage({
            action: 'toggleDomain',
            domain: domain,
            protect: false
          });
          if (result.success) {
            renderDomains(result.state.protectedDomainsList || []);
          }
        }
      );
    });
  });
}

// ---- Change Password ----

document.getElementById('btn-change-password').addEventListener('click', async () => {
  const current = document.getElementById('current-password').value;
  const newPass = document.getElementById('new-password').value;
  const confirm = document.getElementById('confirm-password').value;
  const errorEl = document.getElementById('password-error');
  const successEl = document.getElementById('password-success');

  errorEl.classList.add('hidden');
  successEl.classList.add('hidden');

  if (!current || !newPass || !confirm) {
    errorEl.textContent = 'All fields are required.';
    errorEl.classList.remove('hidden');
    return;
  }

  if (newPass.length < 8) {
    errorEl.textContent = 'New password must be at least 8 characters.';
    errorEl.classList.remove('hidden');
    return;
  }

  if (newPass !== confirm) {
    errorEl.textContent = 'New passwords do not match.';
    errorEl.classList.remove('hidden');
    return;
  }

  const result = await browser.runtime.sendMessage({
    action: 'changePassword',
    currentPassword: current,
    newPassword: newPass
  });

  if (result.success) {
    successEl.textContent = 'Password changed successfully.';
    successEl.classList.remove('hidden');
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
  } else {
    errorEl.textContent = result.error || 'Failed to change password.';
    errorEl.classList.remove('hidden');
  }
});

// ---- Reset Everything ----

document.getElementById('btn-reset').addEventListener('click', () => {
  showModal(
    'This will permanently delete all encrypted cookies, settings, and your master password. You will need to set up K\'s Vault again. This cannot be undone.',
    async () => {
      await browser.runtime.sendMessage({ action: 'panicWipe' });
      window.close();
    }
  );
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

// ---- Start ----

init();
