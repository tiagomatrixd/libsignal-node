'use strict';

// Backward compatibility exports
exports.crypto = require('./src/crypto');
exports.curve = require('./src/curve');
exports.keyhelper = require('./src/keyhelper');
exports.ProtocolAddress = require('./src/protocol_address');
exports.SessionBuilder = require('./src/session_builder');
exports.SessionCipher = require('./src/session_cipher');
exports.SessionRecord = require('./src/session_record');
Object.assign(exports, require('./src/errors'));

// New optimized exports
exports.messages = require('./src/messages');
exports.constants = require('./src/constants/protocol_constants');
exports.utils = {
    ValidationUtils: require('./src/utils/validation_utils'),
    KeyHelper: require('./src/utils/key_helper').KeyHelper
};
exports.crypto_engine = require('./src/crypto/crypto_engine');
