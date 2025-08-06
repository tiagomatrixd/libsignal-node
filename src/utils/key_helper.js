// vim: ts=4:sw=4:expandtab
'use strict';

const curve = require('../curve');
const ValidationUtils = require('../utils/validation_utils');
const nodeCrypto = require('crypto');

/**
 * Optimized KeyHelper class for libsignal-node
 * Provides key generation and management with context and validation
 */
class KeyHelper {
    
    constructor() {
        // Context for maintaining generated keys and avoiding regeneration
        this._generatedKeys = new Map();
        this._keyCache = new Map();
        this._maxCacheSize = 50;
    }
    
    /**
     * Generate an identity key pair
     * @returns {Object} Identity key pair with pubKey and privKey
     */
    generateIdentityKeyPair() {
        return curve.generateKeyPair();
    }
    
    /**
     * Generate a registration ID
     * @returns {number} Random registration ID (14-bit)
     */
    generateRegistrationId() {
        const registrationId = Uint16Array.from(nodeCrypto.randomBytes(2))[0];
        return registrationId & 0x3fff; // 14-bit mask
    }
    
    /**
     * Generate a signed prekey with validation and context
     * @param {Object} identityKeyPair - Identity key pair for signing
     * @param {number} signedKeyId - ID for the signed prekey
     * @returns {Object} Signed prekey object
     */
    generateSignedPreKey(identityKeyPair, signedKeyId) {
        ValidationUtils.assertKeyPair(identityKeyPair, 'identityKeyPair');
        
        if (!identityKeyPair.privKey) {
            throw new TypeError('identityKeyPair must have a private key for signing');
        }
        
        ValidationUtils.assertNonNegativeInteger(signedKeyId, 'signedKeyId');
        
        // Check cache first
        const cacheKey = `signed_${signedKeyId}_${identityKeyPair.pubKey.toString('hex')}`;
        if (this._keyCache.has(cacheKey)) {
            return this._keyCache.get(cacheKey);
        }
        
        const keyPair = curve.generateKeyPair();
        const signature = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);
        
        const result = {
            keyId: signedKeyId,
            keyPair: keyPair,
            signature: signature
        };
        
        // Cache the result
        this._cacheResult(cacheKey, result);
        
        // Track generated key
        this._generatedKeys.set(signedKeyId, {
            type: 'signed',
            keyPair: keyPair,
            timestamp: Date.now()
        });
        
        return result;
    }
    
    /**
     * Generate a prekey with validation and context
     * @param {number} keyId - ID for the prekey
     * @returns {Object} Prekey object
     */
    generatePreKey(keyId) {
        ValidationUtils.assertNonNegativeInteger(keyId, 'keyId');
        
        // Check if we already generated this key
        if (this._generatedKeys.has(keyId)) {
            const existing = this._generatedKeys.get(keyId);
            if (existing.type === 'prekey') {
                return {
                    keyId,
                    keyPair: existing.keyPair
                };
            }
        }
        
        const keyPair = curve.generateKeyPair();
        const result = {
            keyId,
            keyPair
        };
        
        // Track generated key
        this._generatedKeys.set(keyId, {
            type: 'prekey',
            keyPair: keyPair,
            timestamp: Date.now()
        });
        
        return result;
    }
    
    /**
     * Generate multiple prekeys at once for efficiency
     * @param {number} startId - Starting ID for prekeys
     * @param {number} count - Number of prekeys to generate
     * @returns {Object[]} Array of prekey objects
     */
    generatePreKeys(startId, count) {
        ValidationUtils.assertNonNegativeInteger(startId, 'startId');
        ValidationUtils.assertNonNegativeInteger(count, 'count');
        
        if (count <= 0) {
            throw new Error('count must be greater than 0');
        }
        
        if (count > 1000) {
            throw new Error('count must not exceed 1000 for performance reasons');
        }
        
        const preKeys = [];
        for (let i = 0; i < count; i++) {
            preKeys.push(this.generatePreKey(startId + i));
        }
        
        return preKeys;
    }
    
    /**
     * Verify if a key ID has been generated
     * @param {number} keyId - Key ID to check
     * @returns {boolean} True if key has been generated
     */
    hasGeneratedKey(keyId) {
        return this._generatedKeys.has(keyId);
    }
    
    /**
     * Get information about a generated key
     * @param {number} keyId - Key ID to look up
     * @returns {Object|null} Key information or null if not found
     */
    getGeneratedKeyInfo(keyId) {
        return this._generatedKeys.get(keyId) || null;
    }
    
    /**
     * Remove old generated keys from tracking
     * @param {number} maxAge - Maximum age in milliseconds (default: 7 days)
     */
    cleanupOldKeys(maxAge = 7 * 24 * 60 * 60 * 1000) {
        const now = Date.now();
        for (const [keyId, keyInfo] of this._generatedKeys.entries()) {
            if (now - keyInfo.timestamp > maxAge) {
                this._generatedKeys.delete(keyId);
            }
        }
    }
    
    /**
     * Validate a signed prekey
     * @param {Object} signedPreKey - Signed prekey to validate
     * @param {Object} identityKeyPair - Identity key pair for verification
     * @returns {boolean} True if valid
     */
    validateSignedPreKey(signedPreKey, identityKeyPair) {
        try {
            ValidationUtils.assertNonNegativeInteger(signedPreKey.keyId, 'signedPreKey.keyId');
            ValidationUtils.assertKeyPair(signedPreKey.keyPair, 'signedPreKey.keyPair');
            ValidationUtils.assertBuffer(signedPreKey.signature, 'signedPreKey.signature');
            ValidationUtils.assertKeyPair(identityKeyPair, 'identityKeyPair');
            
            // Verify signature
            curve.verifySignature(
                identityKeyPair.pubKey,
                signedPreKey.keyPair.pubKey,
                signedPreKey.signature
            );
            
            return true;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Cache management helper
     * @private
     */
    _cacheResult(key, value) {
        if (this._keyCache.size >= this._maxCacheSize) {
            const firstKey = this._keyCache.keys().next().value;
            this._keyCache.delete(firstKey);
        }
        this._keyCache.set(key, value);
    }
    
    /**
     * Clear all caches and tracking
     */
    clearCache() {
        this._generatedKeys.clear();
        this._keyCache.clear();
    }
    
    /**
     * Get statistics about generated keys
     * @returns {Object} Statistics object
     */
    getStats() {
        const stats = {
            totalGenerated: this._generatedKeys.size,
            cacheSize: this._keyCache.size,
            keyTypes: {
                prekey: 0,
                signed: 0
            }
        };
        
        for (const keyInfo of this._generatedKeys.values()) {
            stats.keyTypes[keyInfo.type]++;
        }
        
        return stats;
    }
}

// Export both class and instance for flexibility
const keyHelper = new KeyHelper();

module.exports = {
    KeyHelper,
    // Backward compatibility exports
    generateIdentityKeyPair: keyHelper.generateIdentityKeyPair.bind(keyHelper),
    generateRegistrationId: keyHelper.generateRegistrationId.bind(keyHelper),
    generateSignedPreKey: keyHelper.generateSignedPreKey.bind(keyHelper),
    generatePreKey: keyHelper.generatePreKey.bind(keyHelper),
    // Export singleton instance
    keyHelper
};
