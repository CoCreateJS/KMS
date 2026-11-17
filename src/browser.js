import {createKMS} from './portable/index.js';
const kms=createKMS(globalThis.crypto);
export const {crypto,aes,sha256,ed25519,rsa,encoding,jwt,jws,jwk}=kms;
export default kms;
