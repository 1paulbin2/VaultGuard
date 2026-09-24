/**
 * VaultGuard Frontend Application Logic
 * Interacts with backend/crypto.js using Web Crypto API.
 */

// Application State
const state = {
    currentView: 'all', // 'all', 'favorites', 'recent'
    searchQuery: '',
    deleteTargetId: null,
    autoLockTimer: null,
    AUTO_LOCK_TIMEOUT_MS: 5 * 60 * 1000 // 5 minutes
};

// SVG Icon Helpers
const ICONS = {
    eye: `<svg class="eye-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
    eyeOff: `<svg class="eye-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
    copy: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
    edit: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
    delete: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`,
    star: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
    starFilled: `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`
};

// DOM Elements Initialization
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    setupLockScreenUI();
    setupEventListeners();
    setupAutoLock();

    if (isUnlocked()) {
        showDashboard();
    } else {
        showLockScreen();
    }
}

// --------------------------------------------------
// LOCK SCREEN FLOWS
// --------------------------------------------------
function setupLockScreenUI() {
    const initialized = isVaultInitialized();
    const lockHeading = document.getElementById('lockHeading');
    const lockSubheading = document.getElementById('lockSubheading');
    const unlockBtnText = document.getElementById('unlockBtnText');
    const confirmGroup = document.getElementById('confirmPasswordGroup');

    if (!initialized) {
        lockHeading.textContent = "Create your Vault";
        lockSubheading.textContent = "Set a strong Master Password to initialize your local encrypted vault.";
        unlockBtnText.textContent = "Create Vault";
        confirmGroup.classList.remove('hidden');
        document.getElementById('confirmMasterPassword').required = true;
    } else {
        lockHeading.textContent = "Unlock Vault";
        lockSubheading.textContent = "Your credentials are encrypted locally on this device.";
        unlockBtnText.textContent = "Unlock Vault";
        confirmGroup.classList.add('hidden');
        document.getElementById('confirmMasterPassword').required = false;
    }
}

async function handleUnlockSubmit(e) {
    e.preventDefault();
    const masterPassword = document.getElementById('masterPassword').value;
    const confirmPassword = document.getElementById('confirmMasterPassword').value;
    const unlockBtn = document.getElementById('unlockBtn');
    const unlockBtnText = document.getElementById('unlockBtnText');
    const unlockSpinner = document.getElementById('unlockSpinner');

    if (!isVaultInitialized()) {
        // Validation for First Setup
        if (masterPassword.length < 8) {
            showToast("Master Password must be at least 8 characters long.", "error");
            return;
        }
        if (masterPassword !== confirmPassword) {
            showToast("Master Passwords do not match!", "error");
            return;
        }
    }

    // UI Loading State (PBKDF2 takes ~300k iterations)
    unlockBtn.disabled = true;
    unlockBtnText.classList.add('hidden');
    unlockSpinner.classList.remove('hidden');

    try {
        // Small delay so spinner updates smoothly before PBKDF2 locks CPU
        await new Promise(r => setTimeout(r, 50));

        let success = false;
        if (!isVaultInitialized()) {
            await createVault(masterPassword);
            success = true;
            showToast("Vault initialized successfully!", "success");
        } else {
            success = await unlockVault(masterPassword);
        }

        if (success) {
            document.getElementById('masterPassword').value = '';
            document.getElementById('confirmMasterPassword').value = '';
            showToast("Vault unlocked successfully.", "success");
            showDashboard();
        } else {
            showToast("Incorrect master password.", "error");
        }
    } catch (err) {
        showToast("Authentication failed: " + err.message, "error");
    } finally {
        unlockBtn.disabled = false;
        unlockBtnText.classList.remove('hidden');
        unlockSpinner.classList.add('hidden');
    }
}

// --------------------------------------------------
// DASHBOARD VIEWS & RENDERING
// --------------------------------------------------
function showLockScreen() {
    document.getElementById('lockScreen').classList.remove('hidden');
    document.getElementById('dashboardScreen').classList.add('hidden');
    setupLockScreenUI();
}

function showDashboard() {
    document.getElementById('lockScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.remove('hidden');
    loadVaultEntries();
}

function loadVaultEntries() {
    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    updateStats(vault);
    renderVaultEntries(vault);
}

function updateStats(vault) {
    const total = vault.length;
    const favorites = vault.filter(e => e.favorite).length;
    
    // Recent: added within last 7 days
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recent = vault.filter(e => e.createdAt && new Date(e.createdAt) >= oneWeekAgo).length;

    document.getElementById('statTotalCount').textContent = total;
    document.getElementById('statFavoritesCount').textContent = favorites;
    document.getElementById('statRecentCount').textContent = recent;
    document.getElementById('allCountBadge').textContent = total;
    document.getElementById('favCountBadge').textContent = favorites;
}

function renderVaultEntries(vault) {
    const grid = document.getElementById('passwordsGrid');
    grid.innerHTML = '';

    // Filter by view tab
    let filtered = [...vault];
    if (state.currentView === 'favorites') {
        filtered = filtered.filter(e => e.favorite);
    } else if (state.currentView === 'recent') {
        const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        filtered = filtered.filter(e => e.createdAt && new Date(e.createdAt) >= oneWeekAgo);
    }

    // Filter by search query
    if (state.searchQuery.trim().length > 0) {
        const query = state.searchQuery.toLowerCase();
        filtered = filtered.filter(e => 
            (e.title && e.title.toLowerCase().includes(query)) ||
            (e.username && e.username.toLowerCase().includes(query))
        );
    }

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div class="glass-card empty-state">
                <div class="empty-icon">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <h3 class="empty-title">${state.searchQuery ? 'No passwords found' : 'Your vault is empty'}</h3>
                <p class="empty-desc">${state.searchQuery ? 'Try adjusting your search keywords.' : 'Add your first password and keep your credentials protected.'}</p>
                <button class="btn btn-primary" onclick="openAddModal()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    <span>+ Add Password</span>
                </button>
            </div>
        `;
        return;
    }

    filtered.forEach(entry => {
        const initial = entry.title ? entry.title.charAt(0).toUpperCase() : 'P';
        const card = document.createElement('div');
        card.className = 'glass-card password-card';
        card.setAttribute('data-id', entry.id);

        card.innerHTML = `
            <div class="card-header">
                <div class="card-service-info">
                    <div class="service-avatar">${initial}</div>
                    <div class="service-details">
                        <span class="service-title">${escapeHTML(entry.title)}</span>
                        <span class="service-username">${escapeHTML(entry.username)}</span>
                    </div>
                </div>
                <button class="favorite-btn ${entry.favorite ? 'active' : ''}" data-action="favorite" data-id="${entry.id}" title="Toggle Favorite">
                    ${entry.favorite ? ICONS.starFilled : ICONS.star}
                </button>
            </div>

            <div class="card-body">
                <span class="password-display" id="pass-${entry.id}">••••••••••••</span>
                <div class="card-actions">
                    <button class="btn btn-secondary btn-reveal" data-action="reveal" data-id="${entry.id}" title="Reveal Password">
                        ${ICONS.eye}
                    </button>
                </div>
            </div>

            <div class="card-actions" style="justify-content: flex-end; width: 100%;">
                <button class="btn btn-secondary btn-copy" data-action="copy" data-id="${entry.id}">
                    ${ICONS.copy} <span>Copy</span>
                </button>
                <button class="btn btn-secondary btn-edit" data-action="edit" data-id="${entry.id}">
                    ${ICONS.edit} <span>Edit</span>
                </button>
                <button class="btn btn-secondary btn-delete" data-action="delete" data-id="${entry.id}" style="color: var(--danger-red);">
                    ${ICONS.delete} <span>Delete</span>
                </button>
            </div>
        `;

        grid.appendChild(card);
    });
}

// Delegate events on Password Cards
document.getElementById('passwordsGrid').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;

    const action = btn.getAttribute('data-action');
    const id = btn.getAttribute('data-id');

    if (action === 'reveal') {
        handleRevealPassword(id, btn);
    } else if (action === 'copy') {
        handleCopyPassword(id);
    } else if (action === 'edit') {
        handleEditPassword(id);
    } else if (action === 'delete') {
        handleOpenDeleteModal(id);
    } else if (action === 'favorite') {
        const isFav = toggleFavorite(id);
        btn.classList.toggle('active', isFav);
        btn.innerHTML = isFav ? ICONS.starFilled : ICONS.star;
        loadVaultEntries();
    }
});

// Reveal Password On-Demand
async function handleRevealPassword(entryId, btnElement) {
    const displaySpan = document.getElementById(`pass-${entryId}`);
    if (!displaySpan) return;

    if (displaySpan.classList.contains('revealed')) {
        // Hide password
        displaySpan.textContent = '••••••••••••';
        displaySpan.classList.remove('revealed');
        btnElement.innerHTML = ICONS.eye;
    } else {
        // Fetch & decrypt password on demand
        try {
            const plain = await getDecryptedPassword(entryId);
            displaySpan.textContent = plain;
            displaySpan.classList.add('revealed');
            btnElement.innerHTML = ICONS.eyeOff;
        } catch (err) {
            showToast("Failed to decrypt: " + err.message, "error");
        }
    }
}

// Copy Password to Clipboard securely
async function handleCopyPassword(entryId) {
    try {
        const plain = await getDecryptedPassword(entryId);
        await navigator.clipboard.writeText(plain);
        showToast("Password copied to clipboard.", "success");

        // Clear clipboard after 45 seconds for extra security
        setTimeout(async () => {
            try {
                const currentClip = await navigator.clipboard.readText();
                if (currentClip === plain) {
                    await navigator.clipboard.writeText('');
                }
            } catch(e) {}
        }, 45000);
    } catch (err) {
        showToast("Failed to copy password: " + err.message, "error");
    }
}

// --------------------------------------------------
// ADD / EDIT PASSWORD MODAL
// --------------------------------------------------
function openAddModal() {
    document.getElementById('editEntryId').value = '';
    document.getElementById('modalTitle').textContent = "Add Password";
    document.getElementById('passwordForm').reset();
    openModal('passwordModal');
}

async function handleEditPassword(entryId) {
    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    const entry = vault.find(e => e.id === entryId);
    if (!entry) return;

    document.getElementById('editEntryId').value = entry.id;
    document.getElementById('modalTitle').textContent = "Edit Password";
    document.getElementById('entryTitle').value = entry.title || '';
    document.getElementById('entryUsername').value = entry.username || '';
    document.getElementById('entryCategory').value = entry.category || 'General';
    document.getElementById('entryFavorite').checked = !!entry.favorite;

    try {
        const plain = await getDecryptedPassword(entry.id);
        document.getElementById('entryPassword').value = plain;
    } catch (e) {
        document.getElementById('entryPassword').value = '';
    }

    openModal('passwordModal');
}

async function handleSavePasswordSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('editEntryId').value;
    const title = document.getElementById('entryTitle').value.trim();
    const username = document.getElementById('entryUsername').value.trim();
    const password = document.getElementById('entryPassword').value;
    const category = document.getElementById('entryCategory').value;
    const favorite = document.getElementById('entryFavorite').checked;

    if (!title || !username || (!id && !password)) {
        showToast("Please complete all required fields.", "warning");
        return;
    }

    try {
        if (id) {
            await updateSecret(id, title, username, password, '', category, favorite);
            showToast("Password updated securely.", "success");
        } else {
            await saveSecret(title, username, password, '', category, favorite);
            showToast("Password saved securely.", "success");
        }
        closeModal('passwordModal');
        loadVaultEntries();
    } catch (err) {
        showToast("Error saving password: " + err.message, "error");
    }
}

// --------------------------------------------------
// DELETE MODAL
// --------------------------------------------------
function handleOpenDeleteModal(entryId) {
    state.deleteTargetId = entryId;
    openModal('deleteModal');
}

function handleConfirmDelete() {
    if (state.deleteTargetId) {
        deleteSecret(state.deleteTargetId);
        showToast("Password deleted.", "info");
        state.deleteTargetId = null;
        closeModal('deleteModal');
        loadVaultEntries();
    }
}

// --------------------------------------------------
// PASSWORD GENERATOR LOGIC
// --------------------------------------------------
function openGeneratorModal() {
    generateNewPassword();
    openModal('generatorModal');
}

function generateNewPassword() {
    const length = parseInt(document.getElementById('lengthSlider').value, 10);
    const useUpper = document.getElementById('genUppercase').checked;
    const useLower = document.getElementById('genLowercase').checked;
    const useNums = document.getElementById('genNumbers').checked;
    const useSyms = document.getElementById('genSymbols').checked;

    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNums) charset += '0123456789';
    if (useSyms) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) {
        showToast("Select at least one character type.", "warning");
        return;
    }

    // Cryptographically secure random selection using Web Crypto API
    const randomBytes = new Uint32Array(length);
    crypto.getRandomValues(randomBytes);

    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset[randomBytes[i] % charset.length];
    }

    document.getElementById('genDisplay').textContent = password;
    updateStrengthMeter(password);
}

function updateStrengthMeter(password) {
    const bar = document.getElementById('genStrengthBar');
    let score = 0;
    if (password.length >= 12) score += 25;
    if (password.length >= 16) score += 25;
    if (/[A-Z]/.test(password)) score += 15;
    if (/[a-z]/.test(password)) score += 15;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;

    bar.style.width = score + '%';
    if (score < 40) bar.style.backgroundColor = 'var(--danger-red)';
    else if (score < 70) bar.style.backgroundColor = 'var(--warning-amber)';
    else bar.style.backgroundColor = 'var(--primary-green)';
}

// --------------------------------------------------
// EVENT LISTENERS & MODAL MANAGEMENT
// --------------------------------------------------
function setupEventListeners() {
    // Unlock Form
    document.getElementById('unlockForm').addEventListener('submit', handleUnlockSubmit);
    
    document.getElementById('toggleLockPassword').addEventListener('click', () => {
        togglePasswordInput('masterPassword');
    });

    // Sidebar & View Navigation
    document.querySelectorAll('.nav-item[data-view], .mobile-nav-item[data-view]').forEach(item => {
        item.addEventListener('click', (e) => {
            const view = item.getAttribute('data-view');
            setActiveView(view);
        });
    });

    // Buttons
    document.getElementById('openAddModalBtn').addEventListener('click', openAddModal);
    document.getElementById('navGeneratorBtn').addEventListener('click', openGeneratorModal);
    document.getElementById('inlineGenerateBtn').addEventListener('click', openGeneratorModal);
    document.getElementById('lockVaultBtn').addEventListener('click', handleLock);

    // Mobile buttons
    const mobileAdd = document.getElementById('mobileAddBtn');
    if (mobileAdd) mobileAdd.addEventListener('click', openAddModal);
    const mobileGen = document.getElementById('mobileGenBtn');
    if (mobileGen) mobileGen.addEventListener('click', openGeneratorModal);
    const mobileLock = document.getElementById('mobileLockBtn');
    if (mobileLock) mobileLock.addEventListener('click', handleLock);

    // Form submission
    document.getElementById('passwordForm').addEventListener('submit', handleSavePasswordSubmit);
    document.getElementById('toggleEntryPasswordBtn').addEventListener('click', () => {
        togglePasswordInput('entryPassword');
    });

    // Delete confirmation
    document.getElementById('confirmDeleteBtn').addEventListener('click', handleConfirmDelete);

    // Generator Controls
    document.getElementById('lengthSlider').addEventListener('input', (e) => {
        document.getElementById('lengthValue').textContent = e.target.value;
        generateNewPassword();
    });
    ['genUppercase', 'genLowercase', 'genNumbers', 'genSymbols'].forEach(id => {
        document.getElementById(id).addEventListener('change', generateNewPassword);
    });
    document.getElementById('generateNewBtn').addEventListener('click', generateNewPassword);
    document.getElementById('copyGenPasswordBtn').addEventListener('click', async () => {
        const text = document.getElementById('genDisplay').textContent;
        if (text && text !== 'Select options') {
            await navigator.clipboard.writeText(text);
            showToast("Generated password copied.", "success");
        }
    });
    document.getElementById('useGeneratedPasswordBtn').addEventListener('click', () => {
        const generated = document.getElementById('genDisplay').textContent;
        if (generated && generated !== 'Select options') {
            document.getElementById('entryPassword').value = generated;
            closeModal('generatorModal');
            if (!document.getElementById('passwordModal').classList.contains('active')) {
                openAddModal();
                document.getElementById('entryPassword').value = generated;
            }
        }
    });

    // Search bar
    document.getElementById('searchInput').addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        loadVaultEntries();
    });

    // Close Modals
    document.querySelectorAll('.closeModalBtn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modal = btn.closest('.modal-overlay');
            if (modal) closeModal(modal.id);
        });
    });

    // Keyboard Accessibility: Escape key closes modals
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(modal => {
                closeModal(modal.id);
            });
        }
    });
}

function togglePasswordInput(id) {
    const field = document.getElementById(id);
    if (field) {
        field.type = field.type === 'password' ? 'text' : 'password';
    }
}

function setActiveView(view) {
    state.currentView = view;
    document.querySelectorAll('.nav-item[data-view]').forEach(item => {
        item.classList.toggle('active', item.getAttribute('data-view') === view);
    });
    
    const titles = {
        all: "All Vault Entries",
        favorites: "Favorite Passwords",
        recent: "Recently Added Passwords"
    };
    document.getElementById('viewSectionTitle').textContent = titles[view] || "Vault Entries";
    loadVaultEntries();
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('active');
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
}

// --------------------------------------------------
// LOCK & AUTO-LOCK MANAGEMENT
// --------------------------------------------------
function handleLock() {
    lockVault();
    state.searchQuery = '';
    document.getElementById('searchInput').value = '';
    showToast("Vault locked.", "info");
    showLockScreen();
}

function setupAutoLock() {
    const resetTimer = () => {
        if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
        if (isUnlocked()) {
            state.autoLockTimer = setTimeout(() => {
                if (isUnlocked()) {
                    lockVault();
                    showToast("Vault automatically locked for security.", "warning");
                    showLockScreen();
                }
            }, state.AUTO_LOCK_TIMEOUT_MS);
        }
    };

    ['click', 'mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
        window.addEventListener(evt, resetTimer, { passive: true });
    });
}

// --------------------------------------------------
// REUSABLE TOAST NOTIFICATION SYSTEM
// --------------------------------------------------
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = '';
    if (type === 'success') icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    else if (type === 'error') icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    else if (type === 'warning') icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    else icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

    toast.innerHTML = `${icon} <span>${escapeHTML(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// Utility HTML escape
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}
