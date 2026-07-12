import hashlib
import random
import string
import fs from 'fs';
import readline from 'readline';

const SALT_CHARS = (string.asciiLowercase + string.digits).split('');

function generateBaseKey(k1, k2, k3) {
    return hashlib.createHash('sha256').update(k1 + k2 + k3).digest();
}

function fastEncrypt(plainText, baseKey) {
    const textBytes = Buffer.from(plainText, 'utf-8');
    const encryptedTokens = [];
    
    const rc = (arr) => arr[Math.floor(Math.random() * arr.length)];
    
    for (const b of textBytes) {
        const totalLength = Math.floor(Math.random() * (12 - 6 + 1)) + 6;
        const lengthMarker = totalLength.toString(16);
        
        const saltLen = totalLength - 1 - 2;
        const saltBytes = Buffer.from(Array.from({ length: saltLen }, () => rc(SALT_CHARS)).join(''));
        
        const charKey = hashlib.createHash('sha256').update(Buffer.concat([baseKey, saltBytes])).digest();
        
        const encryptedByte = b ^ charKey[0];
        
        const token = lengthMarker + saltBytes.toString('utf-8') + encryptedByte.toString(16).padStart(2, '0');
        encryptedTokens.push(token);
    }
    
    return encryptedTokens.join('');
}

function fastDecrypt(cipherText, baseKey) {
    const decryptedBytes = [];
    let idx = 0;
    const cipherLen = cipherText.length;

    try {
        while (idx < cipherLen) {
            const totalLength = parseInt(cipherText[idx], 16);
            
            const salt = Buffer.from(cipherText.slice(idx + 1, idx + totalLength - 2), 'utf-8');
            const hexCode = cipherText.slice(idx + totalLength - 2, idx + totalLength);
            
            const charKey = hashlib.createHash('sha256').update(Buffer.concat([baseKey, salt])).digest();
            const encryptedByte = parseInt(hexCode, 16);
            
            decryptedBytes.push(encryptedByte ^ charKey[0]);
            
            idx += totalLength;
        }
        return Buffer.from(decryptedBytes).toString('utf-8');
    } catch (e) {
        return "【エラー】復号失敗。鍵が違
