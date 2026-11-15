import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const TYPE = 'cryptographic';
const ALGORITHM = 'AES-256-GCM';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const DEFAULT_ROTATION_DELAY = 60_000;
const MAX_TIMER_DELAY = 2_147_000_000;

const error = message => new Error(`[CoCreateKMS] ${message}`);
const asId = value => {
    const id = value?.toString?.() ?? value;
    if (typeof id !== 'string' || !/^[a-f\d]{24}$/i.test(id)) throw error('A valid ObjectId is required.');
    return id.toLowerCase();
};
const newId = () => randomBytes(12).toString('hex');
function json(value) {
    if (Array.isArray(value)) return `[${value.map(json).join(',')}]`;
    if (value && typeof value === 'object')
        return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${json(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
}
const dateValue = (value, label) => {
    if (value == null) return null;
    const time = Date.parse(value);
    if (!Number.isFinite(time)) throw error(`${label} must be a valid date or null.`);
    return new Date(time).toISOString();
};

function tenantContext(input, server) {
    const scopes = input.scopes ?? null;
    if (scopes !== null && typeof scopes !== 'object') throw error('scopes must be an object or array.');
    const entries = Array.isArray(scopes) ? scopes : [scopes];
    const scopedOrganization = entries.find(scope => scope && typeof scope === 'object' && scope.organization_id)?.organization_id;
    const scopedHost = entries.find(scope => scope && typeof scope === 'object' && scope.host)?.host;
    const organization_id = input.organization_id ?? scopedOrganization ?? server.organization_id;
    const host = input.host ?? scopedHost ?? server.host;
    if (organization_id != null) asId(organization_id);
    return { organization_id, host, scopes };
}

function scopeKey(input, server) {
    const { organization_id, host, scopes } = tenantContext(input, server);
    return json({ organization_id, host, scopes });
}

function validateRecord(record) {
    record._id = asId(record._id);
    if (record.key == null) throw error('key must reference the key lineage root ObjectId.');
    record.key = asId(record.key);
    const version = Number(record.version);
    if (!Number.isSafeInteger(version) || version < 1) throw error('version must be a positive integer.');
    record.version = version;
    if (record.rotation != null) {
        const interval = record.rotation.interval == null ? null : Number(record.rotation.interval);
        const delay = record.rotation.delay == null ? DEFAULT_ROTATION_DELAY : Number(record.rotation.delay);
        if (interval !== null && (!Number.isFinite(interval) || interval <= 0))
            throw error('rotation.interval must be positive milliseconds or null.');
        if (!Number.isFinite(delay) || delay < 0) throw error('rotation.delay must be non-negative milliseconds.');
        record.rotation = { ...record.rotation, interval, delay };
    }
    for (const field of ['activates', 'expires', 'revoked', 'deleted']) {
        if (record[field] && Object.hasOwn(record[field], 'on'))
            record[field] = { ...record[field], on: dateValue(record[field].on, `${field}.on`) };
    }
    return record;
}

function idOf(record) {
    try { return asId(record?._id); }
    catch { return undefined; }
}

function lifecycle(record, now = Date.now()) {
    if (record?.destroyed || !record?.keyMaterial) return 'destroyed';
    if (record?.deleted?.on) return 'deleted';
    if (record?.revoked?.on) return 'revoked';
    if (record?.expires?.on && Date.parse(record.expires.on) <= now) return 'expired';
    if (record?.activates?.on && Date.parse(record.activates.on) > now) return 'pending';
    if (record?.verification?.required && record.verification.status !== 'verified') return 'pending';
    return record?.status === 'historical' ? 'historical' : 'active';
}

function publicKey(record) {
    if (!record) return record;
    const { keyMaterial, ...metadata } = record;
    metadata.status = lifecycle(record);
    return metadata;
}

function encryptBytes(data, key, aad) {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM.toLowerCase(), key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    return { ciphertext: ciphertext.toString('base64url'), iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}

function decryptBytes(envelope, key, aad) {
    const decipher = createDecipheriv(ALGORITHM.toLowerCase(), key, Buffer.from(envelope.iv, 'base64url'));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64url'));
    return Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64url')),
        decipher.final()
    ]);
}

/** Initialize KMS on a CoCreate server. No storage work runs until an API method is called. */
export function init(server) {
    const keys = new Map();
    const keyScopes = new Map();
    const keyOrganizations = new Map();
    const rotationTimers = new Map();
    const activationTimers = new Map();
    const rotationLocks = new Map();
    let closed = false;
    const configuredWorkflows = server.kmsConfig?.workflows ?? {};

    async function authorize(input, action, keyId) {
        if (!(input.user_id || input.apikey)) return;
        if (typeof server.authorize?.request !== 'function')
            throw error('Authorization is required for requests carrying user or API-key identity.');
        const { organization_id, host } = tenantContext(input, server);
        await server.authorize.request({
            api: 'kms',
            method: `kms.${action}`,
            organization_id,
            host,
            key: keyId,
            apikey: input.apikey
        }, input.user_id);
    }

    async function runWorkflow(name, data, input = {}, action = 'workflow') {
        if (!name) return null;
        if (typeof server.workflow?.run !== 'function')
            throw error(`Workflow "${name}" is configured for ${action}, but the workflow service is unavailable.`);
        const { organization_id, host } = tenantContext(input, server);
        if (!organization_id || !host)
            throw error(`Organization and host scope are required to run the ${action} workflow.`);
        await authorize(input, action, data?.key?._id ?? data?._id ?? data?.query?._id ?? data?.query?.key);
        const result = await server.workflow.run({
            method: `workflow.${name}`,
            organization_id,
            host,
            data
        });
        const output = result?.data ?? result;
        const errors = [result?.error, output?.error].flatMap(value => Array.isArray(value) ? value : value ? [value] : []);
        if (result?.success === false || output?.success === false || errors.length)
            throw error(errors.map(item => item?.message ?? item).join('; ') || `Workflow "${name}" failed.`);
        return output;
    }

    async function persistKey(key, event, scopes, input = {}) {
        const workflow = configuredWorkflows.store;
        if (!workflow) return false;
        await runWorkflow(workflow, {
            event,
            key: structuredClone(key),
            scopes: structuredClone(scopes ?? null)
        }, { ...input, scopes }, 'store');
        return true;
    }

    function normalizeKey(key, context) {
        if (!key || typeof key !== 'object') throw error('The fetch workflow must return a key document.');
        const record = { ...key };
        if (record.type !== TYPE) throw error(`Fetched key must have type "${TYPE}".`);
        if (Buffer.isBuffer(record.keyMaterial) || record.keyMaterial instanceof Uint8Array) {
            const bytes = Buffer.from(record.keyMaterial);
            record.keyMaterial = bytes.toString('base64url');
            bytes.fill(0);
        }
        const keyMaterial = typeof record.keyMaterial === 'string'
            ? Buffer.from(record.keyMaterial, 'base64url')
            : Buffer.alloc(0);
        const validKeyMaterial = keyMaterial.length === KEY_BYTES;
        keyMaterial.fill(0);
        if (!validKeyMaterial)
            throw error('The fetch workflow must return 32-byte key material as a Buffer or base64url string.');
        record.organization_id ??= context.organization_id;
        validateRecord(record);
        return record;
    }

    async function fetchKey(input, query) {
        const workflow = configuredWorkflows.fetch;
        if (!workflow) return null;
        const data = await runWorkflow(workflow, {
            query,
            scopes: structuredClone(input.scopes ?? null)
        }, input, 'fetch');
        return Object.hasOwn(query, '_id') ? data?.key ?? null : data?.keys ?? [];
    }

    function set({ key, scopes, organization_id, host } = {}) {
        const id = asId(key?._id);
        if (key.type !== TYPE) throw error(`Only type "${TYPE}" documents can be cached.`);
        const context = tenantContext({ scopes, organization_id, host }, server);
        if (key.organization_id && context.organization_id && asId(key.organization_id) !== asId(context.organization_id))
            throw error('The key organization does not match the requested cache scope.');
        context.organization_id ??= key.organization_id ? asId(key.organization_id) : undefined;
        const record = normalizeKey(key, context);
        keys.set(id, record);
        keyScopes.set(id, json(context));
        keyOrganizations.set(id, context.organization_id);
        return publicKey(record);
    }

    async function getRecord({ scopes, _id, ...contextFields } = {}) {
        const id = asId(_id);
        const input = { scopes, ...contextFields };
        const context = tenantContext(input, server);
        const cached = keys.get(id);
        if (cached && keyScopes.get(id) === scopeKey(input, server)) {
            await authorize(input, 'get', id);
            return cached;
        }
        const fetched = await fetchKey(input, { _id: id });
        if (!fetched) return null;
        const record = normalizeKey(fetched, context);
        if (idOf(record) !== id) throw error('The fetch workflow returned a different key ObjectId than requested.');
        set({ key: record, scopes, organization_id: context.organization_id, host: context.host });
        return record;
    }

    async function get(input = {}) {
        return publicKey(await getRecord(input));
    }

    function invalidate({ scopes, organization_id, host, _id } = {}) {
        const cacheScope = scopeKey({ scopes, organization_id, host }, server);
        const requestedId = _id == null ? undefined : asId(_id);
        const cached = requestedId ? keys.get(requestedId) : undefined;
        const rootId = cached ? asId(cached.key ?? cached._id) : requestedId;
        let removed = 0;
        for (const [id, key] of keys) {
            if (keyScopes.get(id) !== cacheScope) continue;
            if (rootId && id !== rootId && asId(key.key ?? key._id) !== rootId) continue;
            keys.delete(id);
            keyScopes.delete(id);
            keyOrganizations.delete(id);
            clearTimeout(activationTimers.get(`${cacheScope}:${id}`));
            activationTimers.delete(`${cacheScope}:${id}`);
            removed++;
        }
        if (rootId) {
            const timerId = `${cacheScope}:${rootId}`;
            clearTimeout(rotationTimers.get(timerId));
            rotationTimers.delete(timerId);
        }
        return removed;
    }

    function scheduleRotation(key, scopes, host) {
        const interval = Number(key.rotation?.interval);
        if (closed || !Number.isFinite(interval) || interval <= 0) return;
        if (['destroyed', 'deleted', 'revoked', 'expired'].includes(lifecycle(key)) || key.verification?.status === 'failed') return;
        const rootId = key.key ?? key._id;
        const lockId = `${scopeKey({ scopes, organization_id: key.organization_id, host }, server)}:${asId(rootId)}`;
        clearTimeout(rotationTimers.get(lockId));
        const createdAt = Date.parse(key.created?.on ?? Date.now());
        const activationAt = Date.parse(key.activates?.on ?? Date.now());
        const dueAt = Math.max(
            (Number.isFinite(createdAt) ? createdAt : Date.now()) + interval,
            Number.isFinite(activationAt) ? activationAt : Date.now()
        );
        const timer = setTimeout(async () => {
            rotationTimers.delete(lockId);
            if (closed) return;
            if (Date.now() < dueAt) return scheduleRotation(key, scopes, host);
            if (key.verification?.required && key.verification.status !== 'verified') {
                const retry = setTimeout(() => scheduleRotation(key, scopes, host), Number(key.verification.retryInterval) || 5_000);
                retry.unref?.();
                rotationTimers.set(lockId, retry);
                return;
            }
            try {
                await rotate({ scopes, host, _id: rootId, automatic: true });
            } catch {
                const retry = setTimeout(async () => {
                    rotationTimers.delete(lockId);
                    if (closed) return;
                    try {
                        await rotate({ scopes, host, _id: rootId, automatic: true });
                    } catch {
                        scheduleRotation(key, scopes, host);
                    }
                }, 30_000);
                retry.unref?.();
                rotationTimers.set(lockId, retry);
            }
        }, Math.min(Math.max(0, dueAt - Date.now()), MAX_TIMER_DELAY));
        timer.unref?.();
        rotationTimers.set(lockId, timer);
    }

    function scheduleActivation(key, scopes, host) {
        if (closed || !key.verification?.required || key.verification.status === 'verified') return;
        const timerId = `${scopeKey({ scopes, organization_id: key.organization_id, host }, server)}:${asId(key._id)}`;
        clearTimeout(activationTimers.get(timerId));
        const activatesAt = Date.parse(key.activates?.on ?? Date.now());
        const dueAt = Number.isFinite(activatesAt) ? activatesAt : Date.now();
        const retryInterval = Number(key.verification.retryInterval) || 5_000;
        const retryAt = Math.min(dueAt, Date.now() + retryInterval);
        const timer = setTimeout(async () => {
            activationTimers.delete(timerId);
            if (closed) return;
            const current = keys.get(asId(key._id)) ?? key;
            let verification;
            try {
                verification = await verifyAvailability({ scopes }, current, current.verification);
            } catch {
                scheduleActivation(current, scopes, host);
                return;
            }
            if (verification.status === 'verified') {
                const updated = {
                    ...current,
                    verification,
                    status: Date.now() >= dueAt ? 'active' : 'pending'
                };
                try {
                    await persistKey(updated, 'key.activated', scopes);
                } catch {
                    scheduleActivation(current, scopes, host);
                    return;
                }
                set({ key: updated, scopes, organization_id: updated.organization_id, host });
                scheduleRotation(updated, scopes, host);
                return;
            }
            const timeoutAt = Number(current.verification.timeoutAt);
            if (!Number.isFinite(timeoutAt) || Date.now() < timeoutAt) {
                scheduleActivation(current, scopes, host);
                return;
            }
            const updated = {
                ...current,
                verification: { ...current.verification, status: 'failed' },
                status: 'pending'
            };
            try {
                await persistKey(updated, 'key.verification-failed', scopes);
            } catch {
                scheduleActivation(current, scopes, host);
                return;
            }
            set({ key: updated, scopes, organization_id: updated.organization_id, host });
        }, Math.min(Math.max(0, retryAt - Date.now()), MAX_TIMER_DELAY));
        timer.unref?.();
        activationTimers.set(timerId, timer);
    }

    async function versionsFor({ scopes, _id, ...contextFields }) {
        const contextInput = { scopes, ...contextFields };
        const first = await getRecord({ ...contextInput, _id });
        if (!first) return [];
        const rootId = asId(first.key ?? first._id);
        const context = tenantContext(contextInput, server);
        const cacheScope = scopeKey(contextInput, server);
        const localRecords = [...keys.entries()]
            .filter(([id]) => keyScopes.get(id) === cacheScope)
            .map(([, record]) => record)
            .filter(record => asId(record.key ?? record._id) === rootId);
        const fetched = await fetchKey(contextInput, { key: rootId });
        const fetchedRecords = Array.isArray(fetched) ? fetched : [];
        const recordsById = new Map([[idOf(first), first]]);
        for (const record of [...localRecords, ...fetchedRecords]) {
            const normalized = normalizeKey(record, context);
            if (asId(normalized.key ?? normalized._id) === rootId) recordsById.set(idOf(normalized), normalized);
        }
        const all = [...recordsById.values()];
        for (const record of all) set({ key: record, scopes, organization_id: context.organization_id, host: context.host });
        return all;
    }

    function eligible(record, now = Date.now()) {
        return lifecycle(record, now) === 'active' &&
            (!record.verification?.required || record.verification.status === 'verified');
    }

    async function currentVersion(input) {
        const records = await versionsFor(input);
        if (!records.length) throw error('No locally available key versions were found.');
        const now = Date.now();
        const latest = records.reduce((a, b) => Number(a.version) > Number(b.version) ? a : b);
        scheduleRotation(latest, input.scopes, input.host);
        for (const record of records) {
            if (record.verification?.required && record.verification.status !== 'verified')
                scheduleActivation(record, input.scopes, input.host);
        }
        const active = records.filter(record => eligible(record, now))
            .sort((a, b) => Number(b.version) - Number(a.version));
        if (!active.length) throw error('No locally eligible key version is available.');
        let selected = active[0];
        for (const record of active) {
            const status = idOf(record) === idOf(active[0]) ? 'active' : 'historical';
            if (record.status !== status) {
                const updated = { ...record, status };
                await persistKey(updated, 'key.status-changed', input.scopes, input);
                set({ key: updated, scopes: input.scopes, organization_id: input.organization_id, host: input.host });
                if (idOf(record) === idOf(selected)) selected = updated;
            }
        }
        return selected;
    }

    async function verifyAvailability(input, key, verify) {
        if (!verify || verify === false) return { required: false, status: 'not-required' };
        const config = typeof verify === 'string' ? { workflow: verify } : verify === true ? {} : verify;
        const workflow = config.workflow ?? configuredWorkflows.verify;
        if (!workflow)
            return {
                required: true, workflow, status: 'pending',
                timeoutAt: Number(config.timeoutAt) || Date.now() + (Number(config.timeout) || 300_000),
                retryInterval: Number(config.retryInterval) || 5_000
            };
        let result;
        try {
            result = await runWorkflow(workflow, {
                key: { _id: key._id, version: key.version, key: key.key },
                scopes: structuredClone(input.scopes ?? null)
            }, input, 'verify');
        } catch {
            result = null;
        }
        const expectedKey = asId(key._id);
        const resultKey = result?.key?._id ?? result?.key;
        const resultVersion = result?.version ?? result?.key?.version;
        const wrongKey = resultKey !== undefined && String(resultKey) !== expectedKey;
        const wrongVersion = resultVersion !== undefined && Number(resultVersion) !== Number(key.version);
        if (result?.error?.length || result?.success === false || result?.verified !== true || wrongKey || wrongVersion)
            return {
                required: true, workflow, status: 'pending',
                timeoutAt: Number(config.timeoutAt) || Date.now() + (Number(config.timeout) || 300_000),
                retryInterval: Number(config.retryInterval) || 5_000
            };
        return { required: true, workflow, status: 'verified', verified: { on: new Date().toISOString() } };
    }

    async function rotate(input = {}) {
        const supplied = await getRecord(input);
        if (!supplied) throw error('Key not found.');
        await authorize(input, 'rotate', supplied._id);
        const rootId = asId(supplied.key ?? supplied._id);
        const lockId = `${scopeKey(input, server)}:${rootId}`;
        if (rotationLocks.has(lockId)) return rotationLocks.get(lockId);
        const operation = (async () => {
            const records = await versionsFor({ ...input, _id: rootId });
            const latest = records.reduce((a, b) => Number(a.version) > Number(b.version) ? a : b);
            const version = Math.max(...records.map(record => Number(record.version) || 0)) + 1;
            const delay = input.delay == null ? (latest.rotation?.delay ?? DEFAULT_ROTATION_DELAY) : Number(input.delay);
            if (!Number.isFinite(delay) || delay < 0) throw error('delay must be non-negative milliseconds.');
            const key = {
                _id: newId(),
                key: rootId,
                name: latest.name,
                description: latest.description,
                tags: latest.tags,
                status: delay ? 'pending' : 'active',
                version,
                algorithm: ALGORITHM,
                keyMaterial: randomBytes(KEY_BYTES).toString('base64url'),
                rotation: latest.rotation ?? { interval: null, delay: DEFAULT_ROTATION_DELAY },
                activates: { on: new Date(Date.now() + delay).toISOString() },
                expires: latest.expires ?? { on: null },
                revoked: { on: null, by: null },
                deleted: { on: null, by: null },
                organization_id: tenantContext(input, server).organization_id,
                type: TYPE
            };
            await persistKey(key, 'key.rotated', input.scopes, input);
            key.verification = await verifyAvailability(input, key, input.verify ?? latest.rotation?.verify);
            if (key.verification.required) await persistKey(key, 'key.verification-pending', input.scopes, input);
            set({ key, scopes: input.scopes, organization_id: input.organization_id, host: input.host });
            scheduleActivation(key, input.scopes, input.host);
            scheduleRotation(key, input.scopes, input.host);
            return publicKey(key);
        })();
        rotationLocks.set(lockId, operation);
        try { return await operation; }
        finally { rotationLocks.delete(lockId); }
    }

    async function generate(input = {}) {
        await authorize(input, 'generate');
        const context = tenantContext(input, server);
        if (!context.organization_id) throw error('Organization scope is required to generate a key.');
        const id = newId();
        const interval = input.rotation?.interval == null ? null : Number(input.rotation.interval);
        const delay = input.rotation?.delay == null ? DEFAULT_ROTATION_DELAY : Number(input.rotation.delay);
        if (interval !== null && (!Number.isFinite(interval) || interval <= 0)) throw error('rotation.interval must be positive milliseconds or null.');
        if (!Number.isFinite(delay) || delay < 0) throw error('rotation.delay must be non-negative milliseconds.');
        const expiresOn = dateValue(input.expires?.on, 'expires.on');
        const key = {
            _id: id,
            key: id,
            ...(input.name ? { name: input.name } : {}),
            ...(input.description ? { description: input.description } : {}),
            ...(Array.isArray(input.tags) ? { tags: input.tags } : {}),
            type: TYPE,
            status: 'active',
            version: 1,
            algorithm: ALGORITHM,
            keyMaterial: randomBytes(KEY_BYTES).toString('base64url'),
            rotation: { interval, delay, ...(input.rotation?.verify ? { verify: input.rotation.verify } : {}) },
            activates: { on: new Date().toISOString() },
            expires: { on: expiresOn },
            revoked: { on: null, by: null },
            deleted: { on: null, by: null },
            organization_id: context.organization_id
        };
        await persistKey(key, 'key.generated', input.scopes, input);
        const saved = key;
        saved.verification = await verifyAvailability(input, saved, input.verify ?? input.rotation?.verify);
        if (saved.verification.required) await persistKey(saved, 'key.verification-pending', input.scopes, input);
        set({ key: saved, scopes: input.scopes, organization_id: input.organization_id, host: input.host });
        scheduleActivation(saved, input.scopes, input.host);
        scheduleRotation(saved, input.scopes, input.host);
        return publicKey(saved);
    }

    async function encrypt(input = {}) {
        await authorize(input, 'encrypt', input._id);
        if (!Object.hasOwn(input, 'data')) throw error('data is required.');
        const key = await currentVersion(input);
        const keyMaterial = Buffer.from(key.keyMaterial, 'base64url');
        if (keyMaterial.length !== KEY_BYTES) throw error('Stored key material is invalid.');
        const dek = randomBytes(KEY_BYTES);
        let plaintext, encoding;
        if (Buffer.isBuffer(input.data)) { plaintext = input.data; encoding = 'buffer'; }
        else if (typeof input.data === 'string') { plaintext = Buffer.from(input.data); encoding = 'string'; }
        else {
            const serialized = JSON.stringify(input.data);
            if (serialized === undefined) throw error('data must be JSON serializable.');
            plaintext = Buffer.from(serialized);
            encoding = 'json';
        }
        const metadataBase = {
            format: 1,
            key: asId(key._id),
            version: key.version,
            algorithm: ALGORITHM,
            encoding,
            context: input.context ?? null
        };
        const aad = Buffer.from(json(metadataBase));
        try {
            const encrypted = encryptBytes(plaintext, dek, aad);
            const wrapped = encryptBytes(dek, keyMaterial, Buffer.from(json({ key: metadataBase.key, version: key.version, purpose: 'wrap-DEK' })));
            const wrappedDEK = Buffer.from(JSON.stringify(wrapped)).toString('base64url');
            return {
                data: encrypted.ciphertext,
                metadata: { ...metadataBase, iv: encrypted.iv, tag: encrypted.tag, wrappedDEK }
            };
        } finally {
            dek.fill(0);
            keyMaterial.fill(0);
        }
    }

    async function decrypt(input = {}) {
        const metadata = input.metadata;
        if (typeof input.data !== 'string' || !metadata?.key) throw error('data and metadata.key are required.');
        await authorize(input, 'decrypt', metadata.key);
        const key = await getRecord({ ...input, _id: metadata.key });
        if (!key) throw error(`Key version not found: ${metadata.key}`);
        const state = lifecycle(key);
        if (['destroyed', 'deleted'].includes(state)) throw error(`Key material is unavailable: ${metadata.key}`);
        if (state === 'revoked' && input.allowRevoked !== true) throw error('Key version is revoked.');
        if (state === 'expired' && input.allowExpired !== true) throw error('Key version is expired.');
        if (metadata.format !== 1 || metadata.algorithm !== ALGORITHM) throw error('Unsupported encryption metadata.');
        const keyMaterial = Buffer.from(key.keyMaterial, 'base64url');
        const wrapAad = Buffer.from(json({ key: asId(key._id), version: key.version, purpose: 'wrap-DEK' }));
        const wrappedDEK = JSON.parse(Buffer.from(metadata.wrappedDEK, 'base64url').toString('utf8'));
        let dek, plaintext;
        try {
            dek = decryptBytes(wrappedDEK, keyMaterial, wrapAad);
            const metadataBase = {
                format: metadata.format,
                key: metadata.key,
                version: metadata.version,
                algorithm: metadata.algorithm,
                encoding: metadata.encoding,
                context: metadata.context ?? null
            };
            plaintext = decryptBytes({ ciphertext: input.data, iv: metadata.iv, tag: metadata.tag }, dek, Buffer.from(json(metadataBase)));
            if (metadata.encoding === 'buffer') return { data: Buffer.from(plaintext) };
            if (metadata.encoding === 'json') return { data: JSON.parse(plaintext.toString('utf8')) };
            return { data: plaintext.toString('utf8') };
        } finally {
            keyMaterial.fill(0);
            dek?.fill(0);
            plaintext?.fill(0);
        }
    }

    async function revoke(input = {}) {
        const key = await getRecord(input);
        if (!key) throw error('Key not found.');
        await authorize(input, 'revoke', key._id);
        const updated = { ...key, revoked: { on: new Date().toISOString(), by: input.user_id ?? input.by ?? null }, status: 'revoked' };
        await persistKey(updated, 'key.revoked', input.scopes, input);
        set({ key: updated, scopes: input.scopes, organization_id: input.organization_id, host: input.host });
        return publicKey(updated);
    }

    async function setExpiration(input = {}) {
        const key = await getRecord(input);
        if (!key) throw error('Key not found.');
        await authorize(input, 'setExpiration', key._id);
        const updated = { ...key, expires: { ...key.expires, on: dateValue(input.on, 'expires.on') } };
        await persistKey(updated, 'key.expiration-changed', input.scopes, input);
        set({ key: updated, scopes: input.scopes, organization_id: input.organization_id, host: input.host });
        return publicKey(updated);
    }

    async function logicalDelete(input = {}) {
        const key = await getRecord(input);
        if (!key) throw error('Key not found.');
        await authorize(input, 'delete', key._id);
        const updated = { ...key, deleted: { on: new Date().toISOString(), by: input.user_id ?? input.by ?? null }, status: 'deleted' };
        await persistKey(updated, 'key.deleted', input.scopes, input);
        keys.delete(asId(key._id));
        keyScopes.delete(asId(key._id));
        keyOrganizations.delete(asId(key._id));
        return publicKey(updated);
    }

    async function destroy(input = {}) {
        const key = await getRecord(input);
        if (!key) throw error('Key not found.');
        await authorize(input, 'destroy', key._id);
        if (input.confirm !== asId(key._id) || input.dependenciesCleared !== true)
            throw error('destroy requires confirm equal to the key ObjectId and dependenciesCleared: true.');
        const destroyed = { ...key, keyMaterial: null, destroyed: true, status: 'destroyed' };
        await persistKey(destroyed, 'key.destroyed', input.scopes, input);
        keys.delete(asId(key._id));
        keyScopes.delete(asId(key._id));
        keyOrganizations.delete(asId(key._id));
        return publicKey(destroyed);
    }

    const api = {
        generate,
        encrypt,
        decrypt,
        get,
        set,
        invalidate,
        rotate,
        revoke,
        setExpiration,
        delete: logicalDelete,
        destroy,
        close() {
            closed = true;
            for (const timer of rotationTimers.values()) clearTimeout(timer);
            for (const timer of activationTimers.values()) clearTimeout(timer);
            rotationTimers.clear();
            activationTimers.clear();
            keys.clear();
            keyScopes.clear();
            keyOrganizations.clear();
        }
    };
    return api;
}

export default { init };
