// vim: ts=4:sw=4:expandtab
'use strict';

/**
 * Message classes export module
 * Centralized exports for all message types
 */

const BaseMessage = require('./base_message');
const WhisperMessage = require('./whisper_message');
const PreKeyWhisperMessage = require('./prekey_whisper_message');
const KeyExchangeMessage = require('./key_exchange_message');

module.exports = {
    BaseMessage,
    WhisperMessage,
    PreKeyWhisperMessage,
    KeyExchangeMessage
};
