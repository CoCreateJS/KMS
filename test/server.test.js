import test from 'node:test';
import assert from 'node:assert/strict';
import KMS, { init, crypto } from '../src/server.js';

test('Node entry preserves the managed default and named init exports', () => {
    assert.equal(KMS.init, init);
    assert.equal(typeof crypto.hash, 'function');
    const managed = init({});
    assert.equal(typeof managed.generate, 'function');
    managed.close();
});

test('managed key lifecycle and envelope format remain compatible', async () => {
    const kms = KMS.init({
        organization_id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
        host: 'kms.example.test'
    });

    try {
        const key = await kms.generate({ name: 'compatibility check' });
        assert.equal(key.type, 'cryptographic');
        assert.equal(Object.hasOwn(key, 'keyMaterial'), false);

        const encrypted = await kms.encrypt({ _id: key._id, data: { message: 'managed' } });
        assert.equal(typeof encrypted.data, 'string');
        assert.equal(encrypted.metadata.key, key._id);
        assert.equal(typeof encrypted.metadata.wrappedDEK, 'string');

        const decrypted = await kms.decrypt(encrypted);
        assert.deepEqual(decrypted.data, { message: 'managed' });
    } finally {
        kms.close();
    }
});
