// Portable JOSE support: compact JWS, signed JWT (JWS compact), and JWK.
// No Node imports. All signing and verification use Web Crypto.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const bytes = value => typeof value === 'string'
    ? encoder.encode(value)
    : value instanceof Uint8Array
        ? value
        : value instanceof ArrayBuffer
            ? new Uint8Array(value)
            : (() => { throw new TypeError('Expected string or bytes'); })();
const supported = new Set(['HS256', 'PS256', 'EdDSA']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const isCryptoKey = value => object(value) &&
    typeof value.type === 'string' &&
    object(value.algorithm) &&
    Array.isArray(value.usages);
const parseJSON = data => {
    const value = JSON.parse(decoder.decode(data));
    if (!object(value)) throw new TypeError('Expected JSON object');
    return value;
};
const canonical = value => JSON.stringify(value);
const allowed = alg => {
    if (!supported.has(alg)) throw new RangeError('Unsupported JOSE algorithm');
    return alg;
};
const noCritical = header => {
    if (own(header, 'crit') || own(header, 'b64'))
        throw new RangeError('Critical and unencoded payload extensions are unsupported');
};

export function createJOSE(webcrypto, encoding) {
    if (!webcrypto?.subtle) throw new Error('Web Crypto is required');
    const { subtle } = webcrypto;
    const decode = encoding.base64urlDecode;
    const encode = encoding.base64urlEncode;
    const algorithm = alg => alg === 'HS256'
        ? { name: 'HMAC', hash: 'SHA-256' }
        : alg === 'PS256'
            ? { name: 'RSA-PSS', hash: 'SHA-256' }
            : 'Ed25519';

    function validateCryptoKey(key, alg, usage) {
        const expected = algorithm(alg);
        const expectedName = typeof expected === 'string' ? expected : expected.name;
        if (!isCryptoKey(key) || key.algorithm.name !== expectedName)
            throw new TypeError(`Key type does not match ${alg}`);

        const expectedType = alg === 'HS256' ? 'secret' : usage === 'sign' ? 'private' : 'public';
        if (key.type !== expectedType || !key.usages.includes(usage))
            throw new TypeError(`Key type or usage does not permit ${usage} with ${alg}`);

        if (alg === 'HS256') {
            if (key.algorithm.hash?.name !== 'SHA-256')
                throw new TypeError('HS256 requires an HMAC/SHA-256 key');
            if (Number(key.algorithm.length) < 256)
                throw new TypeError('HS256 requires a key of at least 256 bits');
        }
        if (alg === 'PS256' && key.algorithm.hash?.name !== 'SHA-256')
            throw new TypeError('PS256 requires an RSA-PSS/SHA-256 key');
        return key;
    }

    const importKey = async (material, { alg = 'EdDSA', usage = 'verify', extractable = false } = {}) => {
        allowed(alg);
        if (!['sign', 'verify'].includes(usage)) throw new RangeError('Invalid JOSE key usage');
        if (isCryptoKey(material)) return validateCryptoKey(material, alg, usage);

        const params = algorithm(alg);
        let key;
        if (object(material) && typeof material.kty === 'string') {
            const expectedKty = alg === 'HS256' ? 'oct' : alg === 'PS256' ? 'RSA' : 'OKP';
            if (material.kty !== expectedKty || (alg === 'EdDSA' && material.crv !== 'Ed25519'))
                throw new TypeError(`JWK type does not match ${alg}`);
            const acceptedJwkAlgorithms = alg === 'EdDSA' ? ['EdDSA', 'Ed25519'] : [alg];
            if (material.alg !== undefined && !acceptedJwkAlgorithms.includes(material.alg))
                throw new TypeError(`JWK algorithm does not match ${alg}`);
            key = await subtle.importKey('jwk', material, params, extractable, [usage]);
        } else if (alg === 'HS256') {
            const secret = bytes(material);
            if (secret.length < 32)
                throw new RangeError('HS256 requires a key of at least 32 bytes');
            key = await subtle.importKey('raw', secret, params, extractable, [usage]);
        } else {
            throw new TypeError('Asymmetric keys must be CryptoKey or JWK');
        }
        return validateCryptoKey(key, alg, usage);
    };

    const signBytes = async (input, key, alg) => {
        const cryptoKey = await importKey(key, { alg, usage: 'sign' });
        const params = alg === 'PS256' ? { name: 'RSA-PSS', saltLength: 32 } : algorithm(alg);
        return new Uint8Array(await subtle.sign(params, cryptoKey, bytes(input)));
    };

    const verifyBytes = async (input, signature, key, alg) => {
        const cryptoKey = await importKey(key, { alg, usage: 'verify' });
        const params = alg === 'PS256' ? { name: 'RSA-PSS', saltLength: 32 } : algorithm(alg);
        return subtle.verify(params, cryptoKey, signature, bytes(input));
    };

    const sign = async (payload, key, { alg = 'EdDSA', header = {} } = {}) => {
        allowed(alg);
        if (!object(header) || (own(header, 'alg') && header.alg !== alg))
            throw new TypeError('Invalid protected header algorithm');
        noCritical(header);
        const protectedHeader = { ...header, alg };
        const part1 = encode(encoder.encode(canonical(protectedHeader)));
        const part2 = encode(bytes(payload));
        const signingInput = `${part1}.${part2}`;
        const signature = await signBytes(signingInput, key, alg);
        return `${signingInput}.${encode(signature)}`;
    };

    const verify = async (compact, key, { alg } = {}) => {
        if (typeof compact !== 'string') throw new TypeError('Expected compact JWS');
        const parts = compact.split('.');
        const validPart = value => /^[A-Za-z0-9_-]*$/.test(value);
        if (parts.length !== 3 || !parts[0] || !parts[2] || !parts.every(validPart))
            throw new TypeError('Invalid compact JWS');
        const header = parseJSON(decode(parts[0]));
        noCritical(header);
        allowed(header.alg);
        if (!alg || alg !== header.alg)
            throw new RangeError('Explicit matching expected algorithm required');
        const payload = decode(parts[1]);
        const signature = decode(parts[2]);
        const valid = await verifyBytes(`${parts[0]}.${parts[1]}`, signature, key, alg);
        if (!valid) throw new Error('Invalid JWS signature');
        return { header, payload };
    };

    const jws = Object.freeze({ sign, verify });
    const jwt = Object.freeze({
        generate: (claims, key, options = {}) => {
            if (!object(claims)) throw new TypeError('JWT claims must be an object');
            return sign(canonical(claims), key, {
                ...options,
                header: { typ: 'JWT', ...options.header }
            });
        },
        verify: async (token, key, {
            alg,
            issuer,
            audience,
            subject,
            clockTolerance = 0,
            now = Math.floor(Date.now() / 1000),
            requireExp = false
        } = {}) => {
            if (!Number.isFinite(clockTolerance) || clockTolerance < 0 || !Number.isFinite(now))
                throw new RangeError('Invalid clock settings');
            if (typeof requireExp !== 'boolean') throw new TypeError('requireExp must be boolean');
            const { header, payload } = await verify(token, key, { alg });
            if (header.typ !== undefined && header.typ !== 'JWT') throw new Error('Invalid JWT type');
            const claims = parseJSON(payload);
            for (const field of ['exp', 'nbf', 'iat']) {
                if (own(claims, field) && (typeof claims[field] !== 'number' || !Number.isFinite(claims[field])))
                    throw new Error(`Invalid ${field} claim`);
            }
            if (requireExp && !own(claims, 'exp')) throw new Error('JWT expiration is required');
            if (own(claims, 'exp') && now - clockTolerance >= claims.exp) throw new Error('JWT expired');
            if (own(claims, 'nbf') && now + clockTolerance < claims.nbf) throw new Error('JWT not active');
            if (issuer !== undefined && claims.iss !== issuer) throw new Error('JWT issuer mismatch');
            if (subject !== undefined && claims.sub !== subject) throw new Error('JWT subject mismatch');
            if (audience !== undefined && !(Array.isArray(claims.aud)
                ? claims.aud.includes(audience)
                : claims.aud === audience)) throw new Error('JWT audience mismatch');
            return claims;
        }
    });

    const required = jwk => {
        if (!object(jwk)) throw new TypeError('Expected JWK');
        const names = jwk.kty === 'RSA'
            ? ['e', 'kty', 'n']
            : jwk.kty === 'EC'
                ? ['crv', 'kty', 'x', 'y']
                : jwk.kty === 'OKP'
                    ? ['crv', 'kty', 'x']
                    : jwk.kty === 'oct'
                        ? ['k', 'kty']
                        : null;
        if (!names || names.some(name => typeof jwk[name] !== 'string'))
            throw new TypeError('Unsupported or incomplete JWK');
        return Object.fromEntries(names.map(name => [name, jwk[name]]));
    };

    const jwk = Object.freeze({
        import: importKey,
        export: async key => subtle.exportKey('jwk', key),
        thumbprint: async key => {
            const material = isCryptoKey(key) ? await subtle.exportKey('jwk', key) : key;
            const digest = await subtle.digest('SHA-256', encoder.encode(canonical(required(material))));
            return encode(new Uint8Array(digest));
        }
    });
    return Object.freeze({ jwt, jws, jwk });
}
