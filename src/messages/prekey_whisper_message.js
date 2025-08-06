// vim: ts=4:sw=4:expandtab
'use strict';

const BaseMessage = require('./base_message');
const WhisperMessage = require('./whisper_message');
const ValidationUtils = require('../utils/validation_utils');
const { cryptoEngine } = require('../crypto/crypto_engine');
const CONSTANTS = require('../constants/protocol_constants');
const protobufs = require('../protobufs');

/**
 * PreKeyWhisperMessage class - optimized OOP implementation
 * Represents a message that includes prekey information for initial key exchange
 */
class PreKeyWhisperMessage extends BaseMessage {
    
    constructor(registrationId = null, preKeyId = null, signedPreKeyId = null, 
                baseKey = null, identityKey = null, message = null) {
        super();
        
        this._registrationId = null;
        this._preKeyId = null;
        this._signedPreKeyId = null;
        this._baseKey = null;
        this._identityKey = null;
        this._message = null; // WhisperMessage instance or Buffer
        this._mac = null;
        
        if (registrationId !== null) this.registrationId = registrationId;
        if (preKeyId !== null) this.preKeyId = preKeyId;
        if (signedPreKeyId !== null) this.signedPreKeyId = signedPreKeyId;
        if (baseKey !== null) this.baseKey = baseKey;
        if (identityKey !== null) this.identityKey = identityKey;
        if (message !== null) this.message = message;
    }
    
    /**
     * Registration ID getter/setter with validation
     */
    get registrationId() {
        return this._registrationId;
    }
    
    set registrationId(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'registrationId');
        }
        this._registrationId = value;
        this._invalidateCache();
    }
    
    /**
     * PreKey ID getter/setter with validation
     */
    get preKeyId() {
        return this._preKeyId;
    }
    
    set preKeyId(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'preKeyId');
        }
        this._preKeyId = value;
        this._invalidateCache();
    }
    
    /**
     * Signed PreKey ID getter/setter with validation
     */
    get signedPreKeyId() {
        return this._signedPreKeyId;
    }
    
    set signedPreKeyId(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'signedPreKeyId');
        }
        this._signedPreKeyId = value;
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
     * Message getter/setter with validation
     */
    get message() {
        return this._message;
    }
    
    set message(value) {
        if (value !== null) {
            if (value instanceof WhisperMessage) {
                this._message = value;
            } else if (Buffer.isBuffer(value)) {
                this._message = value;
            } else {
                throw new TypeError('message must be a WhisperMessage instance or Buffer');
            }
        } else {
            this._message = null;
        }
        this._invalidateCache();
    }
    
    /**
     * MAC getter/setter
     */
    get mac() {
        return this._mac;
    }
    
    set mac(value) {
        if (value !== null) {
            ValidationUtils.assertBuffer(value, 'mac');
        }
        this._mac = value;
    }
    
    /**
     * Get the inner WhisperMessage instance
     * @returns {WhisperMessage|null} WhisperMessage instance
     */
    getWhisperMessage() {
        if (this._message instanceof WhisperMessage) {
            return this._message;
        } else if (Buffer.isBuffer(this._message)) {
            // Deserialize on demand
            try {
                return WhisperMessage.deserialize(this._message);
            } catch (error) {
                throw new Error(`Failed to deserialize inner message: ${error.message}`);
            }
        }
        return null;
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
        if (this._registrationId === null || this._registrationId === undefined) {
            throw new Error('PreKeyWhisperMessage: registrationId is required');
        }
        
        if (this._signedPreKeyId === null || this._signedPreKeyId === undefined) {
            throw new Error('PreKeyWhisperMessage: signedPreKeyId is required');
        }
        
        if (!this._baseKey) {
            throw new Error('PreKeyWhisperMessage: baseKey is required');
        }
        
        if (!this._identityKey) {
            throw new Error('PreKeyWhisperMessage: identityKey is required');
        }
        
        if (!this._message) {
            throw new Error('PreKeyWhisperMessage: message is required');
        }
        
        // Validate inner message if it's a WhisperMessage instance
        if (this._message instanceof WhisperMessage) {
            this._message.validate();
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
        
        let messageBuffer;
        if (this._message instanceof WhisperMessage) {
            messageBuffer = this._message.serialize();
        } else {
            messageBuffer = this._message;
        }
        
        const msg = protobufs.PreKeyWhisperMessage.create({
            registrationId: this._registrationId,
            preKeyId: this._preKeyId,
            signedPreKeyId: this._signedPreKeyId,
            baseKey: this._baseKey,
            identityKey: this._identityKey,
            message: messageBuffer
        });
        
        this._serializedData = Buffer.from(protobufs.PreKeyWhisperMessage.encode(msg).finish());
        return this._serializedData;
    }
    
    /**
     * Create a message with MAC
     * @param {Buffer} ourIdentityKey - Our identity key
     * @param {Buffer} macKey - MAC key for authentication
     * @returns {Buffer} Complete message with MAC
     */
    createWithMAC(ourIdentityKey, macKey) {
        ValidationUtils.assertPublicKey(ourIdentityKey);
        ValidationUtils.assertBuffer(macKey, 'macKey');
        
        const msgBuffer = this.serialize();
        const macInput = this._createMacInput(ourIdentityKey, this._identityKey, msgBuffer);
        const mac = cryptoEngine.calculateMAC(macKey, macInput);
        
        this._mac = mac;
        
        // Combine message and MAC
        const result = Buffer.alloc(msgBuffer.length + mac.length);
        result.set(msgBuffer, 0);
        result.set(mac, msgBuffer.length);
        
        return result;
    }
    
    /**
     * Verify MAC of the message
     * @param {Buffer} ourIdentityKey - Our identity key
     * @param {Buffer} macKey - MAC key for verification
     * @param {number} macLength - Expected MAC length
     * @throws {Error} If MAC verification fails
     */
    verifyMAC(ourIdentityKey, macKey, macLength = CONSTANTS.KEY_SIZES.MAC) {
        if (!this._mac) {
            throw new Error('PreKeyWhisperMessage: MAC not set');
        }
        
        const msgBuffer = this.serialize();
        const macInput = this._createMacInput(ourIdentityKey, this._identityKey, msgBuffer);
        
        cryptoEngine.verifyMAC(macInput, macKey, this._mac, macLength);
    }
    
    /**
     * Deserialize buffer to PreKeyWhisperMessage
     * @param {Buffer} buffer - Buffer to deserialize
     * @returns {PreKeyWhisperMessage} Deserialized message instance
     */
    static deserialize(buffer) {
        ValidationUtils.assertBuffer(buffer, 'buffer');
        
        try {
            const decoded = protobufs.PreKeyWhisperMessage.decode(buffer);
            const message = new PreKeyWhisperMessage(
                decoded.registrationId,
                decoded.preKeyId,
                decoded.signedPreKeyId,
                decoded.baseKey ? Buffer.from(decoded.baseKey) : null,
                decoded.identityKey ? Buffer.from(decoded.identityKey) : null,
                decoded.message ? Buffer.from(decoded.message) : null
            );
            
            message.validate();
            return message;
        } catch (error) {
            throw new Error(`Failed to deserialize PreKeyWhisperMessage: ${error.message}`);
        }
    }
    
    /**
     * Deserialize buffer with MAC
     * @param {Buffer} buffer - Buffer containing message and MAC
     * @param {number} macLength - Length of MAC (default: 32)
     * @returns {Object} Object with message and MAC
     */
    static deserializeWithMAC(buffer, macLength = CONSTANTS.KEY_SIZES.MAC) {
        ValidationUtils.assertBuffer(buffer, 'buffer');
        ValidationUtils.assertNonNegativeInteger(macLength, 'macLength');
        
        if (buffer.length < macLength) {
            throw new Error('Buffer too short to contain MAC');
        }
        
        const messageLength = buffer.length - macLength;
        const messageBuffer = buffer.slice(0, messageLength);
        const mac = buffer.slice(messageLength);
        
        const message = PreKeyWhisperMessage.deserialize(messageBuffer);
        message.mac = mac;
        
        return { message, mac };
    }
    
    /**
     * Create a copy of this message
     * @returns {PreKeyWhisperMessage} Cloned message
     */
    clone() {
        let clonedMessage = null;
        if (this._message instanceof WhisperMessage) {
            clonedMessage = this._message.clone();
        } else if (Buffer.isBuffer(this._message)) {
            clonedMessage = Buffer.from(this._message);
        }
        
        const cloned = new PreKeyWhisperMessage(
            this._registrationId,
            this._preKeyId,
            this._signedPreKeyId,
            this._baseKey ? Buffer.from(this._baseKey) : null,
            this._identityKey ? Buffer.from(this._identityKey) : null,
            clonedMessage
        );
        
        if (this._mac) {
            cloned.mac = Buffer.from(this._mac);
        }
        
        return cloned;
    }
    
    /**
     * Create a string representation of the message
     * @returns {string} String representation
     */
    toString() {
        return `<PreKeyWhisperMessage(` +
               `registrationId=${this._registrationId}, ` +
               `preKeyId=${this._preKeyId}, ` +
               `signedPreKeyId=${this._signedPreKeyId}, ` +
               `baseKey=${this._baseKey ? this._baseKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `identityKey=${this._identityKey ? this._identityKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `valid=${this._isValid}` +
               `)>`;
    }
}

module.exports = PreKeyWhisperMessage;
