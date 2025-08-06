// vim: ts=4:sw=4:expandtab
'use strict';

const nodeCrypto = require('crypto');
const assert = require('assert');
const CONSTANTS = require('../constants/protocol_constants');
const ValidationUtils = require('../utils/validation_utils');

/**
 * Optimized cryptographic operations for libsignal-node
 * Features memoization for secure operations and improved error handling
 */
class CryptoEngine {
    
    constructor() {
        // Memoization cache for expensive operations (with size limit)
        this._memoCache = new Map();
        this._maxCacheSize = 100;
    }
    
    /**
     * Generate a cache key for memoization
     * @private
     */
    _generateCacheKey(operation, ...params) {
        const keyData = params.map(p => 
            Buffer.isBuffer(p) ? p.toString('hex') : String(p)
        ).join('|');
        return `${operation}:${keyData}`;
    }
    
    /**
     * Get from cache or compute and cache
     * @private
     */
    _memoize(key, computeFn) {
        if (this._memoCache.has(key)) {
            return this._memoCache.get(key);
        }
        
        const result = computeFn();
        
        // Limit cache size
        if (this._memoCache.size >= this._maxCacheSize) {
            const firstKey = this._memoCache.keys().next().value;
            this._memoCache.delete(firstKey);
        }
        
        this._memoCache.set(key, result);
        return result;
    }
    
    /**
     * AES-256-CBC encryption
     * @param {Buffer} key - Encryption key (32 bytes)
     * @param {Buffer} data - Data to encrypt
     * @param {Buffer} iv - Initialization vector (16 bytes)
     * @returns {Buffer} Encrypted data
     */
    encrypt(key, data, iv) {
        ValidationUtils.assertBufferLength(key, CONSTANTS.KEY_SIZES.PRIVATE_KEY, 'key');
        ValidationUtils.assertBuffer(data, 'data');
        ValidationUtils.assertBufferLength(iv, CONSTANTS.KEY_SIZES.IV, 'iv');
        
        const cipher = nodeCrypto.createCipheriv(CONSTANTS.CRYPTO.AES_MODE, key, iv);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }
    
    /**
     * AES-256-CBC decryption
     * @param {Buffer} key - Decryption key (32 bytes)
     * @param {Buffer} data - Data to decrypt
     * @param {Buffer} iv - Initialization vector (16 bytes)
     * @returns {Buffer} Decrypted data
     */
    decrypt(key, data, iv) {
        ValidationUtils.assertBufferLength(key, CONSTANTS.KEY_SIZES.PRIVATE_KEY, 'key');
        ValidationUtils.assertBuffer(data, 'data');
        ValidationUtils.assertBufferLength(iv, CONSTANTS.KEY_SIZES.IV, 'iv');
        
        const decipher = nodeCrypto.createDecipheriv(CONSTANTS.CRYPTO.AES_MODE, key, iv);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    /**
     * Calculate HMAC with retry mechanism and memoization for safe operations
     * @param {Buffer} key - HMAC key
     * @param {Buffer} data - Data to authenticate
     * @returns {Buffer} HMAC digest
     */
    calculateMAC(key, data) {
        ValidationUtils.assertBuffer(key, 'key');
        ValidationUtils.assertBuffer(data, 'data');
        
        // For certain safe operations, we can use memoization
        const canMemoize = key.length === CONSTANTS.KEY_SIZES.MAC && data.length < 1024;
        const cacheKey = canMemoize ? this._generateCacheKey('mac', key, data) : null;
        
        if (canMemoize && this._memoCache.has(cacheKey)) {
            return this._memoCache.get(cacheKey);
        }
        
        let attempts = 0;
        while (attempts < CONSTANTS.RETRY.MAC_CALCULATION_ATTEMPTS) {
            try {
                const hmac = nodeCrypto.createHmac(CONSTANTS.CRYPTO.HMAC_ALGORITHM, key);
                hmac.update(data);
                const result = Buffer.from(hmac.digest());
                
                if (canMemoize) {
                    this._memoCache.set(cacheKey, result);
                }
                
                return result;
            } catch (error) {
                console.error(`Error calculating MAC on attempt ${attempts + 1}:`, error);
                attempts++;
                if (attempts === CONSTANTS.RETRY.MAC_CALCULATION_ATTEMPTS) {
                    throw new Error(`Failed to calculate MAC after ${CONSTANTS.RETRY.MAC_CALCULATION_ATTEMPTS} attempts`);
                }
            }
        }
    }
    
    /**
     * Calculate SHA-512 hash
     * @param {Buffer} data - Data to hash
     * @returns {Buffer} Hash digest
     */
    hash(data) {
        ValidationUtils.assertBuffer(data, 'data');
        
        const sha512 = nodeCrypto.createHash(CONSTANTS.CRYPTO.HASH_512);
        sha512.update(data);
        return sha512.digest();
    }
    
    /**
     * Derive secrets using HKDF (RFC 5869) - optimized implementation
     * @param {Buffer} input - Input key material
     * @param {Buffer} salt - Salt (must be 32 bytes)
     * @param {Buffer} info - Info parameter
     * @param {number} chunks - Number of chunks to return (1-3)
     * @returns {Buffer[]} Array of derived secrets
     */
    deriveSecrets(input, salt, info, chunks = CONSTANTS.MESSAGE_KEYS.HKDF_CHUNKS) {
        ValidationUtils.assertBuffer(input, 'input');
        ValidationUtils.assertBufferLength(salt, CONSTANTS.KEY_SIZES.SALT, 'salt');
        ValidationUtils.assertBuffer(info, 'info');
        
        if (chunks < 1 || chunks > CONSTANTS.MESSAGE_KEYS.MAX_HKDF_CHUNKS) {
            throw new Error(`chunks must be between 1 and ${CONSTANTS.MESSAGE_KEYS.MAX_HKDF_CHUNKS}`);
        }
        
        // Check cache for this derivation
        const cacheKey = this._generateCacheKey('derive', input, salt, info, chunks);
        if (this._memoCache.has(cacheKey)) {
            return this._memoCache.get(cacheKey);
        }
        
        // Extract phase
        const PRK = this.calculateMAC(salt, input);
        
        // Expand phase
        const infoArray = new Uint8Array(info.byteLength + 1 + CONSTANTS.KEY_SIZES.MAC);
        infoArray.set(info, CONSTANTS.KEY_SIZES.MAC);
        infoArray[infoArray.length - 1] = 1;
        
        const signed = [this.calculateMAC(PRK, Buffer.from(infoArray.slice(CONSTANTS.KEY_SIZES.MAC)))];
        
        for (let i = 2; i <= chunks; i++) {
            infoArray.set(signed[signed.length - 1]);
            infoArray[infoArray.length - 1] = i;
            signed.push(this.calculateMAC(PRK, Buffer.from(infoArray)));
        }
        
        // Cache the result
        if (this._memoCache.size < this._maxCacheSize) {
            this._memoCache.set(cacheKey, signed);
        }
        
        return signed;
    }
    
    /**
     * Verify HMAC with constant-time comparison
     * @param {Buffer} data - Data that was authenticated
     * @param {Buffer} key - HMAC key
     * @param {Buffer} mac - MAC to verify
     * @param {number} length - Expected MAC length
     * @throws {Error} If MAC verification fails
     */
    verifyMAC(data, key, mac, length) {
        ValidationUtils.assertBuffer(data, 'data');
        ValidationUtils.assertBuffer(key, 'key');
        ValidationUtils.assertBuffer(mac, 'mac');
        
        if (mac.length !== length) {
            throw new Error(`Expected MAC length: ${length}, received: ${mac.length}`);
        }
        
        const calculatedMac = this.calculateMAC(key, data).slice(0, length);
        
        if (!nodeCrypto.timingSafeEqual(calculatedMac, mac)) {
            throw new Error("MAC verification failed");
        }
    }
    
    /**
     * Clear the memoization cache
     */
    clearCache() {
        this._memoCache.clear();
    }
    
    /**
     * Get cache statistics
     * @returns {Object} Cache statistics
     */
    getCacheStats() {
        return {
            size: this._memoCache.size,
            maxSize: this._maxCacheSize
        };
    }
}

// Export both the class and a singleton instance for backward compatibility
const cryptoEngine = new CryptoEngine();

module.exports = {
    CryptoEngine,
    // Backward compatibility - export singleton methods
    encrypt: cryptoEngine.encrypt.bind(cryptoEngine),
    decrypt: cryptoEngine.decrypt.bind(cryptoEngine),
    calculateMAC: cryptoEngine.calculateMAC.bind(cryptoEngine),
    hash: cryptoEngine.hash.bind(cryptoEngine),
    deriveSecrets: cryptoEngine.deriveSecrets.bind(cryptoEngine),
    verifyMAC: cryptoEngine.verifyMAC.bind(cryptoEngine),
    // Export singleton instance
    cryptoEngine
};
