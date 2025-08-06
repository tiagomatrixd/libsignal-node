// vim: ts=4:sw=4:expandtab
'use strict';

/**
 * Protocol constants for libsignal-node
 * Centralized constants to avoid magic numbers throughout the codebase
 */

const PROTOCOL_CONSTANTS = {
    // Protocol version
    VERSION: 3,
    
    // Key sizes
    KEY_SIZES: {
        PRIVATE_KEY: 32,
        PUBLIC_KEY: 33,
        MAC: 32,
        IV: 16,
        SALT: 32
    },
    
    // Bit operations
    BITS: {
        TUPLE_MASK: 0xf,
        TUPLE_SHIFT: 4,
        MAX_TUPLE_VALUE: 15
    },
    
    // Crypto algorithms
    CRYPTO: {
        AES_MODE: 'aes-256-cbc',
        HASH_ALGORITHM: 'sha256',
        HASH_512: 'sha512',
        HMAC_ALGORITHM: 'sha256'
    },
    
    // Message keys
    MESSAGE_KEYS: {
        DERIVE_INFO: 'WhisperMessageKeys',
        HKDF_CHUNKS: 3,
        MAX_HKDF_CHUNKS: 3
    },
    
    // Session limits
    SESSION: {
        MAX_OLD_SESSIONS: 40,
        MAX_MESSAGE_KEYS: 2000
    },
    
    // Error retry limits
    RETRY: {
        MAC_CALCULATION_ATTEMPTS: 3,
        DEFAULT_ATTEMPTS: 3
    }
};

// Freeze the object to prevent modifications
Object.freeze(PROTOCOL_CONSTANTS);
Object.freeze(PROTOCOL_CONSTANTS.KEY_SIZES);
Object.freeze(PROTOCOL_CONSTANTS.BITS);
Object.freeze(PROTOCOL_CONSTANTS.CRYPTO);
Object.freeze(PROTOCOL_CONSTANTS.MESSAGE_KEYS);
Object.freeze(PROTOCOL_CONSTANTS.SESSION);
Object.freeze(PROTOCOL_CONSTANTS.RETRY);

module.exports = PROTOCOL_CONSTANTS;
