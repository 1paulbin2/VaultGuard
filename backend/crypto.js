// VaultGuard Client-Side Cryptographic Backend

// Helper functions

// Convert a string into Uint8Array bytes (supports unicode/emojis)
function text_to_hex(text) {
    const encoder = new TextEncoder();
    return encoder.encode(text);
}

// Convert buffer back into string text
function hex_to_text(buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

// Convert Uint8Array bytes into hexadecimal string for storage
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Convert hexadecimal string back into Uint8Array bytes
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

// Generate cryptographically secure random salt (16 bytes)
function salt_generator() {
    return crypto.getRandomValues(new Uint8Array(16));
}

// Generate master AES-GCM 256 key from master password and salt using PBKDF2 (300,000 iterations)
async function generate_master_key(password_text, salt_bytes) {
    let hex = text_to_hex(password_text);
    const base_key = await crypto.subtle.importKey(
        'raw',
        hex,
        'PBKDF2',
        false,
        ['deriveKey']
    );
    const aes_key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt_bytes,
            iterations: 300000,
            hash: 'SHA-256'
        },
        base_key,
        { name: 'AES-GCM', length: 256 },
        false,                            // Non-extractable
        ['encrypt', 'decrypt']
    );

    return aes_key;
}

// Encrypt plain text using AES-GCM key with random 12-byte IV
async function encrypt_password(plain_text, aes_key) {
    const data_bytes = text_to_hex(plain_text);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        aes_key,
        data_bytes
    );

    return {
        ciphertext: new Uint8Array(ciphertextBuffer),
        iv: iv
    };
}

// Decrypt ciphertext using AES-GCM key and IV bytes
async function decrypt_password(ciphertext_bytes, iv_bytes, aes_key) {
    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv_bytes },
        aes_key,
        ciphertext_bytes
    );

    return hex_to_text(decryptedBuffer);
}

// Active key in memory during unlocked session
let activeKey = null;

// Constant verification token used to safely verify master password without storing it
const VERIFICATION_CONSTANT = "VAULTGUARD_AUTH_VERIFY_V1";

// Check if vault has been initialized
function isVaultInitialized() {
    return !!localStorage.getItem('pm_salt') && !!localStorage.getItem('pm_verifier');
}

// Setup a new vault with master password
async function createVault(masterPassword) {
    const newSalt = salt_generator();
    const saltHex = bytesToHex(newSalt);
    
    // Derive AES key
    const aesKey = await generate_master_key(masterPassword, newSalt);
    
    // Encrypt verification token
    const encryptedVerification = await encrypt_password(VERIFICATION_CONSTANT, aesKey);
    const verifierObj = {
        ciphertextHex: bytesToHex(encryptedVerification.ciphertext),
        ivHex: bytesToHex(encryptedVerification.iv)
    };

    localStorage.setItem('pm_salt', saltHex);
    localStorage.setItem('pm_verifier', JSON.stringify(verifierObj));
    if (!localStorage.getItem('pm_vault')) {
        localStorage.setItem('pm_vault', JSON.stringify([]));
    }
    
    activeKey = aesKey;
}

// Unlock vault with master password
async function unlockVault(masterPassword) {
    let saltHex = localStorage.getItem('pm_salt');
    let verifierJson = localStorage.getItem('pm_verifier');

    if (!saltHex || !verifierJson) {
        // Fallback or legacy initialization: create verifier with provided password
        await createVault(masterPassword);
        return true;
    }

    const saltBytes = hexToBytes(saltHex);
    const candidateKey = await generate_master_key(masterPassword, saltBytes);
    
    const verifierObj = JSON.parse(verifierJson);
    const ciphertextBytes = hexToBytes(verifierObj.ciphertextHex);
    const ivBytes = hexToBytes(verifierObj.ivHex);

    try {
        const decryptedText = await decrypt_password(ciphertextBytes, ivBytes, candidateKey);
        if (decryptedText === VERIFICATION_CONSTANT) {
            activeKey = candidateKey;
            return true;
        } else {
            return false;
        }
    } catch (e) {
        // AES-GCM decryption tag check fails on wrong key
        return false;
    }
}

// Save a secret entry to vault
async function saveSecret(title, username, plainPassword, notes = '', category = 'General', isFavorite = false) {
    if (!activeKey) throw new Error("Vault is locked!");

    const encrypted = await encrypt_password(plainPassword, activeKey);

    const newEntry = {
        id: Date.now().toString() + '_' + Math.random().toString(36).substring(2, 7),
        title,
        username,
        ciphertextHex: bytesToHex(encrypted.ciphertext),
        ivHex: bytesToHex(encrypted.iv),
        notes: notes || '',
        category: category || 'General',
        favorite: !!isFavorite,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    vault.push(newEntry);
    localStorage.setItem('pm_vault', JSON.stringify(vault));
    return newEntry;
}

// Update existing secret entry in vault
async function updateSecret(entryId, title, username, plainPassword, notes = '', category = 'General', isFavorite = false) {
    if (!activeKey) throw new Error("Vault is locked!");

    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    const index = vault.findIndex(item => item.id === entryId);
    if (index === -1) throw new Error("Entry not found");

    let ciphertextHex = vault[index].ciphertextHex;
    let ivHex = vault[index].ivHex;

    // Only re-encrypt if password is updated/provided
    if (plainPassword && plainPassword.trim().length > 0) {
        const encrypted = await encrypt_password(plainPassword, activeKey);
        ciphertextHex = bytesToHex(encrypted.ciphertext);
        ivHex = bytesToHex(encrypted.iv);
    }

    vault[index] = {
        ...vault[index],
        title,
        username,
        ciphertextHex,
        ivHex,
        notes: notes || '',
        category: category || 'General',
        favorite: !!isFavorite,
        updatedAt: new Date().toISOString()
    };

    localStorage.setItem('pm_vault', JSON.stringify(vault));
    return vault[index];
}

// Toggle favorite status for an entry
function toggleFavorite(entryId) {
    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    const index = vault.findIndex(item => item.id === entryId);
    if (index !== -1) {
        vault[index].favorite = !vault[index].favorite;
        localStorage.setItem('pm_vault', JSON.stringify(vault));
        return vault[index].favorite;
    }
    return false;
}

// Delete entry from vault
function deleteSecret(entryId) {
    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    const filtered = vault.filter(item => item.id !== entryId);
    localStorage.setItem('pm_vault', JSON.stringify(filtered));
}

// Retrieve decrypted password on demand
async function getDecryptedPassword(entryId) {
    if (!activeKey) throw new Error("Vault is locked!");

    const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
    const entry = vault.find(item => item.id === entryId);

    if (!entry) throw new Error("Entry not found");

    const ciphertextBytes = hexToBytes(entry.ciphertextHex);
    const ivBytes = hexToBytes(entry.ivHex);

    return await decrypt_password(ciphertextBytes, ivBytes, activeKey);
}

// Lock vault and wipe active key from memory
function lockVault() {
    activeKey = null;
}

// Check active unlocked status
function isUnlocked() {
    return activeKey !== null;
}
