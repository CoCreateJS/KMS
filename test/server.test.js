import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import KMS, { init, crypto, kms } from '../src/server.js';

test('Node entry preserves the managed default and named init exports', () => {
    assert.equal(KMS.init, init);
    assert.equal(typeof crypto.hash, 'function');
    const server = {};
    const managed = init(server);
    assert.equal(init(server), managed);
    assert.equal(typeof managed.generate, 'function');
    managed.close();
});

test('Node server KMS helper namespace preserves synchronous consumer helpers', () => {
    const rsa = kms.generateKeyPair('rsa', { modulusLength: 2048 });
    const token = kms.generateJWT({ payload: { sub: 'kms-consumer' } }, rsa.privateKey, 'RS256');
    assert.deepEqual(kms.verifyJWT(token, rsa.publicKey, 'RS256'), { sub: 'kms-consumer' });

    const ec = kms.generateKeyPair('ec', { namedCurve: 'prime256v1' });
    const jwk = kms.exportJwk(ec.privateKey);
    assert.equal(kms.getJwkThumbprint(jwk).length > 0, true);
    const jws = JSON.parse(kms.createJWS({ alg: 'ES256' }, 'payload', ec.privateKey));
    assert.equal(Buffer.from(jws.signature, 'base64url').length, 64);

    const vapidKeys = kms.generateVapidKeys();
    const authorization = kms.createVapidToken({
        audience: 'https://push.example.test',
        subject: 'mailto:contact@example.test',
        publicKey: vapidKeys.publicKey
    }, vapidKeys.privateKey);
    const vapidToken = authorization.match(/vapid t=([^,]+)/)?.[1];
    assert.ok(vapidToken);
    assert.equal(Buffer.from(vapidToken.split('.')[2], 'base64url').length, 64);
    const point = Buffer.from(vapidKeys.publicKey, 'base64url');
    const vapidPublicKey = createPublicKey({
        key: {
            kty: 'EC',
            crv: 'P-256',
            x: point.subarray(1, 33).toString('base64url'),
            y: point.subarray(33).toString('base64url')
        },
        format: 'jwk'
    });
    assert.ok(kms.verifyJWT(vapidToken, vapidPublicKey, 'ES256'));
});

test('managed key lifecycle and envelope format remain compatible', async () => {
    const records = new Map();
    const server = {
        crud: {
            async send(request) {
                if (request.organization_id !== 'aaaaaaaaaaaaaaaaaaaaaaaa' || request.host !== 'kms.example.test')
                    return { error: 'tenant context missing' };
                if (request.method === 'object.create') {
                    records.set(request.object._id, structuredClone(request.object));
                    return { object: [request.object] };
                }
                if (request.method === 'object.update') {
                    records.set(request.object._id, { ...records.get(request.object._id), ...structuredClone(request.object) });
                    return { object: [records.get(request.object._id)] };
                }
                if (request.method === 'object.read') {
                    const found = [...records.values()].filter(record =>
                        Object.entries(request.filter.query).every(([key, value]) => record[key] === value));
                    return { object: structuredClone(found) };
                }
                return { error: `unsupported method: ${request.method}` };
            }
        }
    };
    const kms = KMS.init(server);
    const tenant = { organization_id: 'aaaaaaaaaaaaaaaaaaaaaaaa', host: 'kms.example.test' };

    try {
        const key = await kms.generate({ ...tenant, name: 'compatibility check' });
        assert.equal(key.type, 'cryptographic');
        assert.equal(Object.hasOwn(key, 'keyMaterial'), false);

        const encrypted = await kms.encrypt({ ...tenant, _id: key._id, data: { message: 'managed' } });
        assert.equal(typeof encrypted.data, 'string');
        assert.equal(encrypted.metadata.key, key._id);
        assert.equal(typeof encrypted.metadata.wrappedDEK, 'string');

        const decrypted = await kms.decrypt({ ...tenant, ...encrypted });
        assert.deepEqual(decrypted.data, { message: 'managed' });
    } finally {
        kms.close();
    }
});
