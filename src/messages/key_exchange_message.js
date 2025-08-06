// vim: ts=4:sw=4:expandtab
'use strict';

const BaseMessage = require('./base_message');
const ValidationUtils = require('../utils/validation_utils');
const { cryptoEngine } = require('../crypto/crypto_engine');
const CONSTANTS = require('../constants/protocol_constants');
const protobufs = require('../protobufs');

/**
 * KeyExchangeMessage class - optimized OOP implementation
 * Represents a key exchange message for establishing initial sessions
 */
class KeyExchangeMessage extends BaseMessage {
    
    constructor(id = null, baseKey = null, ephemeralKey = null, 
                identityKey = null, baseKeySignature = null) {
        super();
        
        this._id = null;
        this._baseKey = null;
        this._ephemeralKey = null;
        this._identityKey = null;
        this._baseKeySignature = null;
        
        if (id !== null) this.id = id;
        if (baseKey !== null) this.baseKey = baseKey;
        if (ephemeralKey !== null) this.ephemeralKey = ephemeralKey;
        if (identityKey !== null) this.identityKey = identityKey;
        if (baseKeySignature !== null) this.baseKeySignature = baseKeySignature;
    }
    
    /**
     * ID getter/setter with validation
     */
    get id() {
        return this._id;
    }
    
    set id(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'id');
        }
        this._id = value;
        this._invalidateCache();
    }
    
    /**
     * Base key getter/setter with validation
     */
    get baseKey() {
        return this._baseKey;
    }
    
    set baseKey(value) {
        if (value !== null) {
            ValidationUtils.assertPublicKey(value);
        }
        this._baseKey = value;
        this._invalidateCache();
    }
    
    /**
     * Ephemeral key getter/setter with validation
     */
    get ephemeralKey() {
        return this._ephemeralKey;
    }
    
    set ephemeralKey(value) {
        if (value !== null) {
            ValidationUtils.assertPublicKey(value);
        }
        this._ephemeralKey = value;
        this._invalidateCache();
    }
    
    /**
     * Identity key getter/setter with validation
     */
    get identityKey() {
        return this._identityKey;
    }
    
    set identityKey(value) {
        if (value !== null) {
            ValidationUtils.assertPublicKey(value);
        }
        this._identityKey = value;
        this._invalidateCache();
    }
    
    /**
     * Base key signature getter/setter with validation
     */
    get baseKeySignature() {
        return this._baseKeySignature;
    }
    
    set baseKeySignature(value) {
        if (value !== null) {
            ValidationUtils.assertBuffer(value, 'baseKeySignature');
        }
        this._baseKeySignature = value;
        this._invalidateCache();
    }
    
    /**
     * Invalidate cached data when properties change
     * @private
     */
    _invalidateCache() {
        this._serializedData = null;
        this._isValid = false;
    }
    
    /**
     * Validate the message structure
     * @throws {Error} If validation fails
     */
    validate() {
        if (this._id === null || this._id === undefined) {
            throw new Error('KeyExchangeMessage: id is required');
        }
        
        if (!this._baseKey) {
            throw new Error('KeyExchangeMessage: baseKey is required');
        }
        
        if (!this._ephemeralKey) {
            throw new Error('KeyExchangeMessage: ephemeralKey is required');
        }
        
        if (!this._identityKey) {
            throw new Error('KeyExchangeMessage: identityKey is required');
        }
        
        if (!this._baseKeySignature) {
            throw new Error('KeyExchangeMessage: baseKeySignature is required');
        }
        
        this._isValid = true;
    }
    
    /**
     * Serialize the message to buffer
     * @returns {Buffer} Serialized message
     */
    serialize() {
        this.validate();
        
        // Return cached version if available
        if (this._serializedData) {
            return this._serializedData;
        }
        
        const msg = protobufs.KeyExchangeMessage.create({
            id: this._id,
            baseKey: this._baseKey,
            ephemeralKey: this._ephemeralKey,
            identityKey: this._identityKey,
            baseKeySignature: this._baseKeySignature
        });
        
        this._serializedData = Buffer.from(protobufs.KeyExchangeMessage.encode(msg).finish());
        return this._serializedData;
    }
    
    /**
     * Verify the base key signature
     * @param {Function} verifySignature - Signature verification function
     * @throws {Error} If signature verification fails
     */
    verifyBaseKeySignature(verifySignature) {
        if (!this._identityKey || !this._baseKey || !this._baseKeySignature) {
            throw new Error('KeyExchangeMessage: Cannot verify signature - missing required fields');
        }
        
        try {
            verifySignature(this._identityKey, this._baseKey, this._baseKeySignature);
        } catch (error) {
            throw new Error(`KeyExchangeMessage: Base key signature verification failed: ${error.message}`);
        }
    }
    
    /**
     * Deserialize buffer to KeyExchangeMessage
     * @param {Buffer} buffer - Buffer to deserialize
     * @returns {KeyExchangeMessage} Deserialized message instance
     */
    static deserialize(buffer) {
        ValidationUtils.assertBuffer(buffer, 'buffer');
        
        try {
            const decoded = protobufs.KeyExchangeMessage.decode(buffer);
            const message = new KeyExchangeMessage(
                decoded.id,
                decoded.baseKey ? Buffer.from(decoded.baseKey) : null,
                decoded.ephemeralKey ? Buffer.from(decoded.ephemeralKey) : null,
                decoded.identityKey ? Buffer.from(decoded.identityKey) : null,
                decoded.baseKeySignature ? Buffer.from(decoded.baseKeySignature) : null
            );
            
            message.validate();
            return message;
        } catch (error) {
            throw new Error(`Failed to deserialize KeyExchangeMessage: ${error.message}`);
        }
    }
    
    /**
     * Check if this message is a response to another key exchange
     * @param {KeyExchangeMessage} otherMessage - Other message to compare
     * @returns {boolean} True if this is a response message
     */
    isResponse(otherMessage) {
        ValidationUtils.assertInstanceOf(otherMessage, KeyExchangeMessage, 'otherMessage');
        
        // Response messages typically have higher ID and different keys
        return this._id > otherMessage._id &&
               !this._baseKey.equals(otherMessage._baseKey) &&
               !this._ephemeralKey.equals(otherMessage._ephemeralKey);
    }
    
    /**
     * Generate a response message to this key exchange
     * @param {number} responseId - ID for the response message
     * @param {Object} ourKeys - Our key pair objects
     * @param {Function} signFunction - Function to sign the base key
     * @returns {KeyExchangeMessage} Response message
     */
    generateResponse(responseId, ourKeys, signFunction) {
        ValidationUtils.assertNonNegativeInteger(responseId, 'responseId');
        
        if (!ourKeys.identityKey || !ourKeys.baseKey || !ourKeys.ephemeralKey) {
            throw new Error('Missing required keys for response generation');
        }
        
        const signature = signFunction(ourKeys.identityKey.privKey, ourKeys.baseKey.pubKey);
        
        return new KeyExchangeMessage(
            responseId,
            ourKeys.baseKey.pubKey,
            ourKeys.ephemeralKey.pubKey,
            ourKeys.identityKey.pubKey,
            signature
        );
    }
    
    /**
     * Create a copy of this message
     * @returns {KeyExchangeMessage} Cloned message
     */
    clone() {
        const cloned = new KeyExchangeMessage(
            this._id,
            this._baseKey ? Buffer.from(this._baseKey) : null,
            this._ephemeralKey ? Buffer.from(this._ephemeralKey) : null,
            this._identityKey ? Buffer.from(this._identityKey) : null,
            this._baseKeySignature ? Buffer.from(this._baseKeySignature) : null
        );
        
        return cloned;
    }
    
    /**
     * Create a string representation of the message
     * @returns {string} String representation
     */
    toString() {
        return `<KeyExchangeMessage(` +
               `id=${this._id}, ` +
               `baseKey=${this._baseKey ? this._baseKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `ephemeralKey=${this._ephemeralKey ? this._ephemeralKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `identityKey=${this._identityKey ? this._identityKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `valid=${this._isValid}` +
               `)>`;
    }
}

module.exports = KeyExchangeMessage;
