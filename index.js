const {  createHmac } = require('crypto');
const ed = require('@noble/ed25519');
const express = require('express');
const bodyParser = require('body-parser');
const { sign } = require('holonym-wasm-issuer');
const { poseidon } = require('circomlibjs-old'); //The new version gives wrong outputs of Poseidon hash that disagree with ZoKrates and are too big for the max scalar in the field
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
const port = 3000;
const msg = 'DO NOT SIGN THIS UNLESS YOU ARE ON https://holonym.id';
const subgroupOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041n

const _prf = input => {
    const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC);
    hmac.update(input); 
    return (BigInt('0x'+hmac.digest('hex')) % subgroupOrder).toString();
}

// Signs the ephemeral "pubkey" given as prfSeed, and signature is used as easy-to-code proof of discrete log
const authorizedPRF = async (pubkey, sig) => {
    if(await _verify(pubkey,sig)) {
        let p = _prf(pubkey);
        const commit = poseidon([BigInt('0x'+pubkey).toString(), p]);
        return {
            prfSeed: pubkey,
            prf: p,
            boundToSeed: commit.toString(),
            sig: sign(process.env.HOLONYM_SECRET_EDDSA, commit.toString())
        }
    } else {
        throw 'Error verifying knowledge of discrete log (in this case, via EdDSA signature)';
    }
}

const _verify = async (pubkey, sig) => {
    return await ed.verify(sig, Buffer.from(msg), pubkey)
}


/* ****************** */

app.post('/', async (req, res) => {
    res.setTimeout(1500);

    res.send(await authorizedPRF(req.body.pubkey, req.body.sig));
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
    msg: msg
}