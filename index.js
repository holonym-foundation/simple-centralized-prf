const { createVerify, createHmac } = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
const port = 3000;

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
    const verify = createVerify('SHA256');
    verify.update('DO NOT SIGN THIS UNLESS YOU ARE ON https://holonym.id');
    verify.end();
    return verify.verify(pubkey, sig);
}












app.post('/', (req, res) => {
    console.log("body", req.body)
  res.send(authorizedPRF(req.body.pubkey, req.body.sig));
})

app.listen(port, () => {})
module.exports = {
    server: app
}