import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createKMS } from '../src/portable/index.js';

const { jwt, jws, jwk } = createKMS(webcrypto);
const ed25519Pair = () => webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

test('EdDSA JWS roundtrip supports an empty payload and rejects tampering', async () => {
    const { privateKey, publicKey } = await ed25519Pair();
    const token = await jws.sign('hello', privateKey);
    const result = await jws.verify(token, publicKey, { alg: 'EdDSA' });
    assert.equal(new TextDecoder().decode(result.payload), 'hello');

    const emptyToken = await jws.sign('', privateKey);
    const emptyResult = await jws.verify(emptyToken, publicKey, { alg: 'EdDSA' });
    assert.equal(emptyResult.payload.length, 0);

    const parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    await assert.rejects(() => jws.verify(parts.join('.'), publicKey, { alg: 'EdDSA' }));
    await assert.rejects(() => jws.verify(token, publicKey, { alg: 'HS256' }));
});

test('JWT applies expiration, issuer, audience, and subject policy', async () => {
    const { privateKey, publicKey } = await ed25519Pair();
    const now = Math.floor(Date.now() / 1000);
    const token = await jwt.generate({
        iss: 'issuer', aud: 'audience', sub: 'subject', exp: now + 60, nbf: now - 5
    }, privateKey);

    const claims = await jwt.verify(token, publicKey, {
        alg: 'EdDSA', issuer: 'issuer', audience: 'audience', subject: 'subject', requireExp: true
    });
    assert.equal(claims.iss, 'issuer');
    await assert.rejects(() => jwt.verify(token, publicKey, { alg: 'EdDSA', issuer: 'wrong' }));
    await assert.rejects(() => jwt.verify(token, publicKey, { alg: 'EdDSA', audience: 'wrong' }));
    await assert.rejects(() => jwt.verify(token, publicKey, { alg: 'EdDSA', now: now + 120 }));
    await assert.rejects(() => jwt.verify(token, publicKey));

    const noExpiry = await jwt.generate({ sub: 'subject' }, privateKey);
    assert.equal((await jwt.verify(noExpiry, publicKey, { alg: 'EdDSA' })).sub, 'subject');
    await assert.rejects(
        () => jwt.verify(noExpiry, publicKey, { alg: 'EdDSA', requireExp: true }),
        /expiration is required/
    );
});

test('HS256 enforces key length and CryptoKey algorithm matching', async () => {
    const secret = webcrypto.getRandomValues(new Uint8Array(32));
    const token = await jws.sign('payload', secret, { alg: 'HS256' });
    assert.equal(new TextDecoder().decode((await jws.verify(token, secret, { alg: 'HS256' })).payload), 'payload');
    await assert.rejects(() => jws.sign('payload', new Uint8Array(31), { alg: 'HS256' }), /32 bytes/);

    const wrongHashKey = await webcrypto.subtle.importKey(
        'raw', new Uint8Array(32), { name: 'HMAC', hash: 'SHA-384' }, false, ['sign']
    );
    await assert.rejects(() => jws.sign('payload', wrongHashKey, { alg: 'HS256' }), /HMAC\/SHA-256/);
});

test('PS256 signs and verifies with RSA-PSS/SHA-256 keys', async () => {
    const pair = await webcrypto.subtle.generateKey({
        name: 'RSA-PSS', hash: 'SHA-256', modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1])
    }, true, ['sign', 'verify']);
    const token = await jws.sign('payload', pair.privateKey, { alg: 'PS256' });
    assert.equal(new TextDecoder().decode((await jws.verify(token, pair.publicKey, { alg: 'PS256' })).payload), 'payload');
});

test('JWK import, export, and thumbprint work across key pairs', async () => {
    const { privateKey, publicKey } = await ed25519Pair();
    const publicJwk = await jwk.export(publicKey);
    const privateJwk = await jwk.export(privateKey);
    assert.equal(await jwk.thumbprint(publicJwk), await jwk.thumbprint(privateJwk));
    const imported = await jwk.import(publicJwk, { alg: 'EdDSA' });
    const token = await jws.sign('hello', privateKey);
    await jws.verify(token, imported, { alg: 'EdDSA' });
    assert.match(await jwk.thumbprint(publicJwk), /^[A-Za-z0-9_-]{43}$/);
});

test('JWS rejects unsupported algorithms, mismatched keys, and critical headers', async () => {
    const { privateKey, publicKey } = await ed25519Pair();
    await assert.rejects(() => jws.sign('hello', privateKey, { alg: 'none' }));
    await assert.rejects(() => jws.sign('hello', privateKey, { header: { crit: ['b64'] } }));
    await assert.rejects(() => jws.sign('hello', privateKey, { alg: 'PS256' }), /does not match/);
    const token = await jws.sign('hello', privateKey);
    await assert.rejects(() => jws.verify(token, publicKey, { alg: 'PS256' }));
});
