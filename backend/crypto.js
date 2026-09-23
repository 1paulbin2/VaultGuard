// helper functions

// convert a string into hex eg hello -> [hex1, hex2, hex3, hex4, hex5]
function text_to_hex(text)
{
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text); // encoder allows for emojis to be encoded into the password
    return bytes
}

// convert a hex into text [hex1, hex2, hex3, hex4, hex5] -> hello
function hex_to_text(buffer)
{
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

// this converts bytes into hex, for easier, faster and more efficient storage
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// converst hex back into binary bytes
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// add noise
function salt_generator()
{
    return crypto.getRandomValues(new Uint8Array(16))
}

// generate the master key to the vault
async function generate_master_key(password_text, salt_bytes)
{
    let hex = text_to_hex(password_text);
    const base_key = await crypto.subtle.importKey(
        'raw',
        hex,
        'PBKDF2',
        false,
        ['deriveKey']
    )
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
    )

    return aes_key;
}

// encrypt text using our AES key
async function encrypt_password(plain_text, aes_key)
{
  const data_bytes = text_to_hex(plain_text)

  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv // Pass the IV to the algorithm
    },
    aes_key,
    data_bytes
  );

  return {
    ciphertext: new Uint8Array(ciphertextBuffer),
    iv: iv
  };
}

// decrypt text using our AES key, iv_bytes are just random numbers, essentially noise
async function decrypt_password(ciphertext_bytes, iv_bytes, aes_key) {
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv_bytes },
    aes_key,
    ciphertext_bytes
  );

  return hex_to_text(decryptedBuffer);
}

// just a demo to run the vault on how its going to work, or how it should work
async function run_demo() {
  console.log("Starting Password Vault Test");

  // Setup Vault (First time)
  const master_password = "MySuperSecretMasterPassword!123";
  const vault_salt = salt_generator(); // Save this salt to disk/localStorage!

  // Unlock / Derive AES Key
  const aes_key = await generate_master_key(master_password, vault_salt);
  console.log("Master key derived successfully:", aes_key);

  // Encrypt a Secret
  const secret_to_store = "GitHub_Pass_2026_#xyz";
  const encrypted_data = await encrypt_password(secret_to_store, aes_key);

  console.log("Encrypted Ciphertext (Bytes):", encrypted_data.ciphertext);
  console.log("Random IV (Bytes):", encrypted_data.iv);

  // Decrypt the Secret
  const recovered_secret = await decrypt_password(
    encrypted_data.ciphertext,
    encrypted_data.iv,
    aes_key
  );

  console.log("Decrypted Secret:", recovered_secret);
}

run_demo();

// keep the key we are using stored
let activeKey = null;

// unlock our vault
async function unlockVault(masterPassword) {
  let saltHex = localStorage.getItem('pm_salt');

  if (!saltHex) {
    // First time setup
    const newSalt = salt_generator();
    saltHex = bytesToHex(newSalt);
    localStorage.setItem('pm_salt', saltHex);
    localStorage.setItem('pm_vault', JSON.stringify([])); // Empty vault
  }

  // Derive key using the saved salt
  const saltBytes = hexToBytes(saltHex);
  activeKey = await generate_master_key(masterPassword, saltBytes);
  console.log("Vault Unlocked!");
}

// save a password
async function saveSecret(title, username, plainPassword) {
  if (!activeKey) throw new Error("Vault is locked!");

  // Encrypt
  const encrypted = await encrypt_password(plainPassword, activeKey);

  // Prepare entry object
  const newEntry = {
    id: Date.now().toString(),
    title,
    username,
    ciphertextHex: bytesToHex(encrypted.ciphertext),
    ivHex: bytesToHex(encrypted.iv)
  };

  // Save to localStorage
  const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
  vault.push(newEntry);
  localStorage.setItem('pm_vault', JSON.stringify(vault));
}

// get encrypted password and decrypt it
async function getDecryptedPassword(entryId) {
  if (!activeKey) throw new Error("Vault is locked!");

  const vault = JSON.parse(localStorage.getItem('pm_vault') || '[]');
  const entry = vault.find(item => item.id === entryId);

  if (!entry) throw new Error("Entry not found");

  const ciphertextBytes = hexToBytes(entry.ciphertextHex);
  const ivBytes = hexToBytes(entry.ivHex);

  // Decrypt on demand
  return await decrypt_password(ciphertextBytes, ivBytes, activeKey);
}

// lock vault
function lockVault() {
  activeKey = null; // Clear key from RAM
  console.log("Vault Locked.");
}