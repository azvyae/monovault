import 'client-only';
import { arrayBufferToBase64, base64ToArrayBuffer } from './client';

const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_FORMAT = 'spki';
const PRIVATE_KEY_FORMAT = 'pkcs8';
const EC_PARAMS = {
  name: 'ECDH',
  namedCurve: 'P-256',
};
const AES_PARAMS = {
  name: 'AES-GCM',
  length: 256,
};

async function generateKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  // Generate the key pair
  const keyPair = await crypto.subtle.generateKey(EC_PARAMS, true, [
    'deriveBits',
  ]);

  // Export the public key in spki format
  const exportedPubKey = await crypto.subtle.exportKey(
    KEY_FORMAT,
    keyPair.publicKey,
  );

  // Export the private key in pkcs8 format
  const exportedPrivKey = await crypto.subtle.exportKey(
    PRIVATE_KEY_FORMAT,
    keyPair.privateKey,
  );

  // Convert to base64 strings
  return {
    publicKey: arrayBufferToBase64(exportedPubKey),
    privateKey: arrayBufferToBase64(exportedPrivKey),
  };
}

/**
 * Encrypt a private key with a passphrase using PBKDF2 and AES-GCM
 */
async function encryptPrivateKey(
  passphrase: string,
  privateKey: string,
): Promise<string> {
  // Generate a random salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // Derive key from passphrase
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey'],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    AES_PARAMS,
    false,
    ['encrypt'],
  );

  // Encrypt the private key
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    new TextEncoder().encode(privateKey),
  );

  // Combine salt + iv + encrypted data
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);

  return arrayBufferToBase64(result.buffer);
}

/**
 * Decrypt a private key using a passphrase
 */
async function decryptPrivateKey(
  passphrase: string,
  encryptedKey: string,
): Promise<string> {
  const encryptedData = base64ToArrayBuffer(encryptedKey);
  const salt = encryptedData.slice(0, SALT_LENGTH);
  const iv = encryptedData.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const data = encryptedData.slice(SALT_LENGTH + IV_LENGTH);

  // Derive the same key from passphrase
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey'],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    AES_PARAMS,
    false,
    ['decrypt'],
  );

  // Decrypt the private key
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    data,
  );

  return new TextDecoder().decode(decrypted);
}

/**
 * Encrypt content for a specific user using their public key
 * Returns: K-eph.ciphertext.IV
 */
async function encryptContent(
  publicKey: string,
  plaintext: string,
): Promise<string> {
  try {
    // Generate ephemeral key pair
    const ephemeralKeyPair = await crypto.subtle.generateKey(EC_PARAMS, true, [
      'deriveBits',
    ]);

    // Import recipient's public key with proper usage
    const recipientPubKey = await crypto.subtle.importKey(
      KEY_FORMAT,
      base64ToArrayBuffer(publicKey),
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable
      ['deriveBits'],
    );

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: recipientPubKey,
      },
      ephemeralKeyPair.privateKey,
      256,
    );

    // Convert shared secret to AES key
    const encryptionKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      AES_PARAMS,
      false,
      ['encrypt'],
    );

    // Generate IV and encrypt the content
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      encryptionKey,
      new TextEncoder().encode(plaintext),
    );

    // Export ephemeral public key
    const exportedEphPubKey = await crypto.subtle.exportKey(
      KEY_FORMAT,
      ephemeralKeyPair.publicKey,
    );

    // Combine K-eph.ciphertext.IV
    const result = new Uint8Array(
      exportedEphPubKey.byteLength + encrypted.byteLength + iv.length,
    );
    result.set(new Uint8Array(exportedEphPubKey), 0);
    result.set(new Uint8Array(encrypted), exportedEphPubKey.byteLength);
    result.set(iv, exportedEphPubKey.byteLength + encrypted.byteLength);

    return arrayBufferToBase64(result.buffer);
  } catch (error) {
    throw new Error('Failed to encrypt');
  }
}

/**
 * Decrypt content using private key
 * Input format: K-eph.ciphertext.IV
 */
async function decryptContent(
  privateKey: string,
  ciphertext: string,
): Promise<string> {
  const data = base64ToArrayBuffer(ciphertext);

  // Import recipient's private key
  const recipientPrivKey = await crypto.subtle.importKey(
    PRIVATE_KEY_FORMAT,
    base64ToArrayBuffer(privateKey),
    EC_PARAMS,
    false,
    ['deriveBits'],
  );

  // Extract components from ciphertext
  const ephPubKeyBytes = 91; // Length of spki format P-256 public key
  const ephPubKey = data.slice(0, ephPubKeyBytes);
  const iv = data.slice(data.byteLength - IV_LENGTH);
  const encryptedData = data.slice(ephPubKeyBytes, data.byteLength - IV_LENGTH);

  // Import ephemeral public key
  const ephemeralPubKey = await crypto.subtle.importKey(
    KEY_FORMAT,
    ephPubKey,
    EC_PARAMS,
    false,
    ['deriveBits'],
  );

  // Derive shared secret using DH
  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: ephemeralPubKey,
    },
    recipientPrivKey,
    256,
  );

  // Convert shared secret to AES key
  const decryptionKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    AES_PARAMS,
    false,
    ['decrypt'],
  );

  // Decrypt the content
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    decryptionKey,
    encryptedData,
  );

  return new TextDecoder().decode(decrypted);
}

export {
  generateKeyPair,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptContent,
  decryptContent,
};
