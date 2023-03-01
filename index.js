const { createHmac } = require('crypto');
require('dotenv').config();

const _prf = input => {
    const hmac = createHmac('sha256', process.env.HMAC_PRF_SECRET);
    hmac.update(input); 
    return hmac.digest('hex');
}

// Signs the ephemeral "pubkey" given as prfSeed, and signature is used as easy-to-code proof of discrete log
const authorizedPRF = (pubkey, sig) => {
    if(_verify(pubkey,sig)) {
        return _prf(pubkey);
    } else {
        throw 'Error verifying knowledge of discrete log (in this case, via ECDSA signature)';
    }
}

const _verify = (pubkey, sig) => {
    const verify = crypto.createVerify('SHA256');
    verify.update('DO NOT SIGN THIS UNLESS YOU ARE ON https://holonym.id');
    verify.end();
    return verify.verify(pubkey, sig);
}