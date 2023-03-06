const {  createHmac, createHash } = require('crypto');
// const ed = require('@noble/ed25519');
const express = require('express');
const bodyParser = require('body-parser');
const { sign } = require('holonym-wasm-issuer');
const { poseidon } = require('circomlibjs-old'); //The new version gives wrong outputs of Poseidon hash that disagree with ZoKrates and are too big for the max scalar in the field
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
const port = 3000;
const msg = 'DO NOT SIGN THIS UNLESS YOU ARE ON https://holonym.id';
const ORDER = 21888242871839275222246405745257275088614511777268538073601725287587578984328n;
// const SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const MAX_MSG = ORDER >> 10n; //Use 10 bits for Koblitz encoding

const _prf = input => {
    const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC);
    hmac.update(input); 
    console.log("PRF OF ", input)
    // console.log((BigInt('0x'+hmac.digest('hex')) % MAX_MSG).toString());
    return (BigInt('0x'+hmac.digest('hex')) % MAX_MSG).toString(16);
}

// Signs the ephemeral "pubkey" given as prfSeed, and signature is used as easy-to-code proof of knowledge of preimage
const authorizedPRF = async (preimage, digest) => {
    console.log("getting prf of ", digest)

    if(_verify(preimage,digest)) {
        let p = _prf(digest);
        const commit = poseidon([digest, p].map(x=>BigInt('0x'+x).toString()));
        return {
            prfSeed: digest,
            prf: p,
            boundToSeed: commit.toString(16),
        }
    } else {
        throw 'Error verifying knowledge of preimage';
    }
}

// Verifies a person knows the preimage of the digest
const _verify = (preimage, digest) => {
    const hash = createHash('sha512');
    hash.update(preimage); 
    return digest === hash.digest('hex');
}


/* ****************** */

app.post('/', async (req, res) => {
    res.setTimeout(1500);

    res.send(await authorizedPRF(req.body.preimage, req.body.digest));
})

app.post('/authority', async (req, res) => {
    res.setTimeout(1500);
    if(req.body.API_KEY == process.env.API_KEY) {
        res.send(_prf(req.body.input));
    } else {
        res.status(401);
    }
})

app.listen(port, () => {})
module.exports = {
    server: app,
    msg: msg,
    MAX_MSG: MAX_MSG, 
}