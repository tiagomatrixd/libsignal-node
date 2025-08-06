// vim: ts=4:sw=4:expandtab
'use strict';

const ValidationUtils = require('../utils/validation_utils');
const CONSTANTS = require('../constants/protocol_constants');

/**
 * Base class for all Signal protocol messages
 * Provides common functionality and validation for message types
 */
class BaseMessage {
    
    constructor() {
        this._version = CONSTANTS.VERSION;
        this._serializedData = null;
        this._isValid = false;
    }
    
    /**
     * Get the protocol version
     * @returns {number} Protocol version
     */
    get version() {
        return this._version;
    }
    
    /**
     * Check if the message is valid
     * @returns {boolean} True if message is valid
     */
    get isValid() {
        return this._isValid;
    }
    
    /**
     * Get the serialized data
     * @returns {Buffer|null} Serialized message data
     */
    get serializedData() {
        return this._serializedData;
    }
    
    /**
     * Validate the message structure
     * Override in subclasses
     * @throws {Error} If validation fails
     */
    validate() {
        throw new Error('validate() must be implemented in subclass');
    }
    
    /**
     * Serialize the message to buffer
     * Override in subclasses
     * @returns {Buffer} Serialized message
     */
    serialize() {
        throw new Error('serialize() must be implemented in subclass');
    }
    
    /**
     * Deserialize buffer to message
     * Override in subclasses
     * @param {Buffer} buffer - Buffer to deserialize
     * @returns {BaseMessage} Deserialized message instance
     */
    static deserialize(buffer) {
        throw new Error('deserialize() must be implemented in subclass');
    }
    
    /**
     * Encode tuple byte for version information
     * @param {number} number1 - First 4-bit number
     * @param {number} number2 - Second 4-bit number
     * @returns {number} Encoded byte
     * @protected
     */
    _encodeTupleByte(number1, number2) {
        ValidationUtils.assertTupleValue(number1, 'number1');
        ValidationUtils.assertTupleValue(number2, 'number2');
        
        return (number1 << CONSTANTS.BITS.TUPLE_SHIFT) | number2;
    }
    
    /**
     * Decode tuple byte to two 4-bit numbers
     * @param {number} byte - Byte to decode
     * @returns {number[]} Array of two 4-bit numbers
     * @protected
     */
    _decodeTupleByte(byte) {
        ValidationUtils.assertNonNegativeInteger(byte, 'byte');
        
        return [
            byte >> CONSTANTS.BITS.TUPLE_SHIFT,
            byte & CONSTANTS.BITS.TUPLE_MASK
        ];
    }
    
    /**
     * Create MAC input buffer for message authentication
     * @param {Buffer} ourIdentityKey - Our identity key
     * @param {Buffer} theirIdentityKey - Their identity key
     * @param {Buffer} messageBuffer - Serialized message
     * @returns {Buffer} MAC input buffer
     * @protected
     */
    _createMacInput(ourIdentityKey, theirIdentityKey, messageBuffer) {
        ValidationUtils.assertPublicKey(ourIdentityKey);
        ValidationUtils.assertPublicKey(theirIdentityKey);
        ValidationUtils.assertBuffer(messageBuffer, 'messageBuffer');
        
        const macInput = Buffer.alloc(
            messageBuffer.byteLength + 
            (CONSTANTS.KEY_SIZES.PUBLIC_KEY * 2) + 
            1
        );
        
        let offset = 0;
        macInput.set(ourIdentityKey, offset);
        offset += CONSTANTS.KEY_SIZES.PUBLIC_KEY;
        
        macInput.set(theirIdentityKey, offset);
        offset += CONSTANTS.KEY_SIZES.PUBLIC_KEY;
        
        macInput[offset] = this._encodeTupleByte(this._version, this._version);
        offset += 1;
        
        macInput.set(messageBuffer, offset);
        
        return macInput;
    }
    
    /**
     * Create a string representation of the message
     * @returns {string} String representation
     */
    toString() {
        return `<${this.constructor.name}(version=${this._version}, valid=${this._isValid})>`;
    }
}

module.exports = BaseMessage;
