import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createKMS } from '../src/portable/index.js';

const node = createKMS(webcrypto);
const browserBackend = createKMS(globalThis.crypto ?? webcrypto);
const hexBytes = value => Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));

test('SHA-256 and HMAC match known vectors', async () => {
    assert.equal(
        await node.sha256.hash('abc'),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    const key = new Uint8Array(20).fill(0x0b);
    assert.equal(
        await node.crypto.hmac('Hi There', key),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    );
});

test('AES-GCM interoperates across Web Crypto contexts and rejects nonce reuse inputs', async () => {
    const key = await node.aes.generateKey();
    const message = 'cross-platform';
    for (const [encryptor, decryptor] of [[node, browserBackend], [browserBackend, node]]) {
        const envelope = await encryptor.aes.encrypt(message, key, { aad: 'context' });
        assert.equal(
            new TextDecoder().decode(await decryptor.aes.decrypt(envelope, key, { aad: 'context' })),
            message
        );
        await assert.rejects(() => decryptor.aes.decrypt(envelope, key, { aad: 'wrong' }));
        await assert.rejects(
            () => encryptor.aes.encrypt(message, key, { iv: new Uint8Array(12) }),
            /generated internally/
        );
    }
});

test('AES-GCM decrypts a NIST AES-128-GCM interoperability vector', async () => {
    const envelope = {
        algorithm: 'aes-128-gcm',
        iv: 'AAAAAAAAAAAAAAAA',
        ciphertext: '',
        tag: node.encoding.base64urlEncode(hexBytes('58e2fccefa7e3061367f1d57a4e7455a'))
    };
    const plaintext = await node.crypto.decrypt(envelope, new Uint8Array(16));
    assert.deepEqual(plaintext, new Uint8Array());
});

test('Ed25519 signatures interoperate across Web Crypto contexts', async () => {
    const pair = await node.ed25519.generateKeyPair();
    const signature = await node.ed25519.sign('hello', pair.privateKey);
    assert.equal(await browserBackend.ed25519.verify('hello', signature, pair.publicKey), true);
    assert.equal(await browserBackend.ed25519.verify('tampered', signature, pair.publicKey), false);
});

test('RSA-PSS signatures interoperate across Web Crypto contexts', async () => {
    const pair = await node.rsa.generateKeyPair({ modulusLength: 2048 });
    const signature = await browserBackend.rsa.pss.sign('hello', pair.privateKey);
    assert.equal(await node.rsa.pss.verify('hello', signature, pair.publicKey), true);
});

test('AES and HMAC CryptoKeys can be imported and exported', async () => {
    const aesBytes = await node.aes.generateKey();
    const aesKey = await node.crypto.importKey(aesBytes, {
        algorithm: 'aes-256-gcm', format: 'raw', extractable: true
    });
    assert.deepEqual(new Uint8Array(await node.crypto.exportKey(aesKey, { format: 'raw' })), aesBytes);

    const hmacBytes = new Uint8Array(32).fill(7);
    const hmacKey = await node.crypto.importKey(hmacBytes, {
        algorithm: 'hmac-sha256', format: 'raw', extractable: true
    });
    assert.deepEqual(new Uint8Array(await node.crypto.exportKey(hmacKey, { format: 'raw' })), hmacBytes);
});

test('encoding roundtrips and rejects malformed or noncanonical input', () => {
    const encoded = node.encoding.base64urlEncode('hello');
    assert.equal(new TextDecoder().decode(browserBackend.encoding.base64urlDecode(encoded)), 'hello');
    assert.throws(() => node.encoding.base64urlDecode('!'));
    assert.throws(() => node.encoding.base64urlDecode('_x'));
    assert.throws(() => node.encoding.hexDecode('0'));
});
