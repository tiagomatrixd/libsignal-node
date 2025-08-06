// vim: ts=4:sw=4:expandtab
'use strict';

const CONSTANTS = require('../constants/protocol_constants');

/**
 * Validation utilities for libsignal-node
 * Centralized validation functions to avoid code duplication
 */
class ValidationUtils {
    
    /**
     * Assert that a value is a Buffer
     * @param {*} value - Value to validate
     * @param {string} paramName - Parameter name for error messages
     * @returns {Buffer} The validated buffer
     * @throws {TypeError} If value is not a Buffer
     */
    static assertBuffer(value, paramName = 'value') {
        if (!(value instanceof Buffer)) {
            throw new TypeError(`${paramName} must be a Buffer, got: ${value?.constructor?.name || typeof value}`);
        }
        return value;
    }
    
    /**
     * Assert that a buffer has the expected length
     * @param {Buffer} buffer - Buffer to validate
     * @param {number} expectedLength - Expected length
     * @param {string} paramName - Parameter name for error messages
     * @returns {Buffer} The validated buffer
     * @throws {TypeError} If buffer length is incorrect
     */
    static assertBufferLength(buffer, expectedLength, paramName = 'buffer') {
        this.assertBuffer(buffer, paramName);
        if (buffer.length !== expectedLength) {
            throw new TypeError(`${paramName} must be ${expectedLength} bytes, got: ${buffer.length}`);
        }
        return buffer;
    }
    
    /**
     * Validate a private key buffer
     * @param {Buffer} privateKey - Private key to validate
     * @returns {Buffer} The validated private key
     * @throws {TypeError} If private key is invalid
     */
    static assertPrivateKey(privateKey) {
        return this.assertBufferLength(privateKey, CONSTANTS.KEY_SIZES.PRIVATE_KEY, 'privateKey');
    }
    
    /**
     * Validate a public key buffer
     * @param {Buffer} publicKey - Public key to validate
     * @returns {Buffer} The validated public key
     * @throws {TypeError} If public key is invalid
     */
    static assertPublicKey(publicKey) {
        return this.assertBufferLength(publicKey, CONSTANTS.KEY_SIZES.PUBLIC_KEY, 'publicKey');
    }
    
    /**
     * Validate a non-negative integer
     * @param {*} value - Value to validate
     * @param {string} paramName - Parameter name for error messages
     * @returns {number} The validated number
     * @throws {TypeError} If value is not a non-negative integer
     */
    static assertNonNegativeInteger(value, paramName = 'value') {
        if (typeof value !== 'number' || (value % 1) !== 0 || value < 0) {
            throw new TypeError(`${paramName} must be a non-negative integer, got: ${value}`);
        }
        return value;
    }
    
    /**
     * Validate a tuple byte value (0-15)
     * @param {number} value - Value to validate
     * @param {string} paramName - Parameter name for error messages
     * @returns {number} The validated value
     * @throws {TypeError} If value is out of range
     */
    static assertTupleValue(value, paramName = 'value') {
        this.assertNonNegativeInteger(value, paramName);
        if (value > CONSTANTS.BITS.MAX_TUPLE_VALUE) {
            throw new TypeError(`${paramName} must be ${CONSTANTS.BITS.MAX_TUPLE_VALUE} or less, got: ${value}`);
        }
        return value;
    }
    
    /**
     * Validate key pair structure
     * @param {Object} keyPair - Key pair to validate
     * @param {string} paramName - Parameter name for error messages
     * @returns {Object} The validated key pair
     * @throws {TypeError} If key pair is invalid
     */
    static assertKeyPair(keyPair, paramName = 'keyPair') {
        if (!keyPair || typeof keyPair !== 'object') {
            throw new TypeError(`${paramName} must be an object`);
        }
        
        if (!keyPair.privKey && !keyPair.pubKey) {
            throw new TypeError(`${paramName} must have either privKey or pubKey`);
        }
        
        if (keyPair.privKey) {
            this.assertPrivateKey(keyPair.privKey);
        }
        
        if (keyPair.pubKey) {
            this.assertPublicKey(keyPair.pubKey);
        }
        
        return keyPair;
    }
    
    /**
     * Validate that an object is an instance of a specific class
     * @param {*} instance - Instance to validate
     * @param {Function} expectedClass - Expected class constructor
     * @param {string} paramName - Parameter name for error messages
     * @returns {*} The validated instance
     * @throws {TypeError} If instance is not of expected type
     */
    static assertInstanceOf(instance, expectedClass, paramName = 'instance') {
        if (!(instance instanceof expectedClass)) {
            throw new TypeError(`${paramName} must be an instance of ${expectedClass.name}`);
        }
        return instance;
    }
}

module.exports = ValidationUtils;
