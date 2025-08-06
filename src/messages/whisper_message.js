// vim: ts=4:sw=4:expandtab
'use strict';

const BaseMessage = require('./base_message');
const ValidationUtils = require('../utils/validation_utils');
const { cryptoEngine } = require('../crypto/crypto_engine');
const CONSTANTS = require('../constants/protocol_constants');
const protobufs = require('../protobufs');

/**
 * WhisperMessage class - optimized OOP implementation
 * Represents an encrypted message in the Signal protocol
 */
class WhisperMessage extends BaseMessage {
    
    constructor(ephemeralKey = null, counter = null, previousCounter = null, ciphertext = null) {
        super();
        
        this._ephemeralKey = null;
        this._counter = null;
        this._previousCounter = null;
        this._ciphertext = null;
        this._mac = null;
        
        if (ephemeralKey !== null) this.ephemeralKey = ephemeralKey;
        if (counter !== null) this.counter = counter;
        if (previousCounter !== null) this.previousCounter = previousCounter;
        if (ciphertext !== null) this.ciphertext = ciphertext;
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
     * Counter getter/setter with validation
     */
    get counter() {
        return this._counter;
    }
    
    set counter(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'counter');
        }
        this._counter = value;
        this._invalidateCache();
    }
    
    /**
     * Previous counter getter/setter with validation
     */
    get previousCounter() {
        return this._previousCounter;
    }
    
    set previousCounter(value) {
        if (value !== null) {
            ValidationUtils.assertNonNegativeInteger(value, 'previousCounter');
        }
        this._previousCounter = value;
        this._invalidateCache();
    }
    
    /**
     * Ciphertext getter/setter with validation
     */
    get ciphertext() {
        return this._ciphertext;
    }
    
    set ciphertext(value) {
        if (value !== null) {
            ValidationUtils.assertBuffer(value, 'ciphertext');
        }
        this._ciphertext = value;
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
        if (!this._ephemeralKey) {
            throw new Error('WhisperMessage: ephemeralKey is required');
        }
        
        if (this._counter === null || this._counter === undefined) {
            throw new Error('WhisperMessage: counter is required');
        }
        
        if (this._previousCounter === null || this._previousCounter === undefined) {
            throw new Error('WhisperMessage: previousCounter is required');
        }
        
        if (!this._ciphertext || this._ciphertext.length === 0) {
            throw new Error('WhisperMessage: ciphertext is required');
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
        
        const msg = protobufs.WhisperMessage.create({
            ephemeralKey: this._ephemeralKey,
            counter: this._counter,
            previousCounter: this._previousCounter,
            ciphertext: this._ciphertext
        });
        
        this._serializedData = Buffer.from(protobufs.WhisperMessage.encode(msg).finish());
        return this._serializedData;
    }
    
    /**
     * Create a message with MAC
     * @param {Buffer} ourIdentityKey - Our identity key
     * @param {Buffer} theirIdentityKey - Their identity key
     * @param {Buffer} macKey - MAC key for authentication
     * @returns {Buffer} Complete message with MAC
     */
    createWithMAC(ourIdentityKey, theirIdentityKey, macKey) {
        ValidationUtils.assertPublicKey(ourIdentityKey);
        ValidationUtils.assertPublicKey(theirIdentityKey);
        ValidationUtils.assertBuffer(macKey, 'macKey');
        
        const msgBuffer = this.serialize();
        const macInput = this._createMacInput(ourIdentityKey, theirIdentityKey, msgBuffer);
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
     * @param {Buffer} theirIdentityKey - Their identity key
     * @param {Buffer} macKey - MAC key for verification
     * @param {number} macLength - Expected MAC length
     * @throws {Error} If MAC verification fails
     */
    verifyMAC(ourIdentityKey, theirIdentityKey, macKey, macLength = CONSTANTS.KEY_SIZES.MAC) {
        if (!this._mac) {
            throw new Error('WhisperMessage: MAC not set');
        }
        
        const msgBuffer = this.serialize();
        const macInput = this._createMacInput(ourIdentityKey, theirIdentityKey, msgBuffer);
        
        cryptoEngine.verifyMAC(macInput, macKey, this._mac, macLength);
    }
    
    /**
     * Deserialize buffer to WhisperMessage
     * @param {Buffer} buffer - Buffer to deserialize
     * @returns {WhisperMessage} Deserialized message instance
     */
    static deserialize(buffer) {
        ValidationUtils.assertBuffer(buffer, 'buffer');
        
        try {
            const decoded = protobufs.WhisperMessage.decode(buffer);
            const message = new WhisperMessage(
                decoded.ephemeralKey ? Buffer.from(decoded.ephemeralKey) : null,
                decoded.counter,
                decoded.previousCounter,
                decoded.ciphertext ? Buffer.from(decoded.ciphertext) : null
            );
            
            message.validate();
            return message;
        } catch (error) {
            throw new Error(`Failed to deserialize WhisperMessage: ${error.message}`);
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
        
        const message = WhisperMessage.deserialize(messageBuffer);
        message.mac = mac;
        
        return { message, mac };
    }
    
    /**
     * Create a copy of this message
     * @returns {WhisperMessage} Cloned message
     */
    clone() {
        const cloned = new WhisperMessage(
            this._ephemeralKey ? Buffer.from(this._ephemeralKey) : null,
            this._counter,
            this._previousCounter,
            this._ciphertext ? Buffer.from(this._ciphertext) : null
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
        return `<WhisperMessage(` +
               `counter=${this._counter}, ` +
               `previousCounter=${this._previousCounter}, ` +
               `ephemeralKey=${this._ephemeralKey ? this._ephemeralKey.toString('hex').slice(0, 8) + '...' : 'null'}, ` +
               `ciphertext=${this._ciphertext ? this._ciphertext.length + ' bytes' : 'null'}, ` +
               `valid=${this._isValid}` +
               `)>`;
    }
}

module.exports = WhisperMessage;
