// vim: ts=4:sw=4

'use strict';

const nodeCrypto = require('crypto');
const assert = require('assert');


function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}


function encrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}


function decrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}


const ALGORITHM = 'sha256';

function calculateMAC(key, data) {
  // Validação de entrada
  if (!Buffer.isBuffer(key) || !Buffer.isBuffer(data)) {
    throw new TypeError('As chaves e os dados devem ser do tipo Buffer.');
  }

  let attempts = 0;
  while (attempts < 3) {
    try {
      const hmac = nodeCrypto.createHmac(ALGORITHM, key);
      hmac.update(data);
      
      return Buffer.from(hmac.digest());
    } catch (error) {
      console.error(`Erro ao calcular o MAC na tentativa ${attempts + 1}:`, error);
      attempts++;
      if (attempts === 3) {
        throw new Error('Falha ao calcular o MAC após 3 tentativas.');
      }
    }
  }
}


function hash(data) {
    assertBuffer(data);
    const sha512 = nodeCrypto.createHash('sha512');
    sha512.update(data);
    return sha512.digest();
}


// Salts always end up being 32 bytes
function deriveSecrets(input, salt, info, chunks) {
    // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    chunks = chunks || 3;
    assert(chunks >= 1 && chunks <= 3);
    const PRK = calculateMAC(salt, input);
    const infoArray = new Uint8Array(info.byteLength + 1 + 32);
    infoArray.set(info, 32);
    infoArray[infoArray.length - 1] = 1;
    const signed = [calculateMAC(PRK, Buffer.from(infoArray.slice(32)))];
    if (chunks > 1) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 2;
        signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
    }
    if (chunks > 2) {
        infoArray.set(signed[signed.length - 1]);
        infoArray[infoArray.length - 1] = 3;
        signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
    }
    return signed;
}

function verifyMAC(data, key, mac, length) {
    if (mac.length !== length) {
        throw new Error(`Comprimento esperado do MAC: ${length}, recebido: ${mac.length}`);
    }
    
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    
    
    if (!nodeCrypto.timingSafeEqual(calculatedMac, mac)) {
        throw new Error("Falha na verificação do MAC");
    }
}

module.exports = {
    deriveSecrets,
    decrypt,
    encrypt,
    hash,
    calculateMAC,
    verifyMAC
};
