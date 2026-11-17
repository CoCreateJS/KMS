import {webcrypto} from 'node:crypto';
import {createKMS} from './portable/index.js';
import managed, {init} from './index.js'; // Existing KMS implementation (unchanged)
const standalone=createKMS(webcrypto);
export const {crypto,aes,sha256,ed25519,rsa,encoding,jwt,jws,jwk}=standalone;
export {init};
export default Object.freeze({...managed,...standalone});
