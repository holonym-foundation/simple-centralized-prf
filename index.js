const {  createHmac, createHash } = require('crypto');
// const ed = require('@noble/ed25519');
const express = require('express');
const bodyParser = require('body-parser');
const { sign, getPubkey, getPubkeyTimes8 } = require('holonym-wasm-issuer');
const { poseidon } = require('circomlibjs-old'); //The new version gives wrong outputs of Poseidon hash that disagree with ZoKrates and are too big for the max scalar in the field
const assert = require('assert');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
const port = 3000;

const ORDER_r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ORDER_n = 21888242871839275222246405745257275088614511777268538073601725287587578984328n;

const SUBORDER = ORDER_n >> 3n; // Order of prime subgroup
const MAX_MSG = ORDER_n >> 10n; //Use 10 bits for Koblitz encoding

// convert big hex strings to big dec strings:
const dec = hex => BigInt('0x'+hex).toString();

/* prf input must be < order r because it will be given as input to the circuit. prf output also must be within Fr,
 * so it can be used within the circuit. but it also must be < MAX_KSG becuase it will be used to make a message-sized
 * pseudorandom point, to be added to the message.
 */
const _prf = input => {
    assert((typeof input === 'bigint') && (input < ORDER_r), `input must be a BigInt less than the bn254 prime ${ORDER_r}`);
    const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC);
    hmac.update(input.toString(16)); 
    return BigInt('0x'+hmac.digest('hex')) % MAX_MSG;
}

// Signs the authenticated (i.e. preimage is known) digest and gives the PRF + signature that this is the PRF result
const authenticatedPRF = async (preimage, digestFr) => {
    if(_verify(preimage,digestFr)) {
        let p = _prf(BigInt(digestFr));
        const commit = poseidon([BigInt(digestFr), p].map(i=>i.toString()));
        console.log(commit, 'is the commitment to', digestFr, p);
        return {
            prfIn: digestFr.toString(),
            prfOut: p.toString(),
            bound: commit.toString(),
            sig: sign(process.env.HOLONYM_SECRET_EDDSA, commit.toString())
        }
    } else {
        throw 'Error verifying knowled`ge of preimage';
    }
}

// Verifies a person knows the preimage of the digest
const _verify = (preimage, digestFr) => {
    const hash = createHash('sha512');
    hash.update(preimage); 
    return BigInt(digestFr) === BigInt('0x'+hash.digest('hex')) % ORDER_r;
}


/* ****************** */

app.post('/', async (req, res) => {
    res.setTimeout(1500);
    res.send(await authenticatedPRF(req.body.preimage, req.body.digestFr));
})

app.post('/authority', async (req, res) => {
    res.setTimeout(1500);
    if(req.body.API_KEY == process.env.API_KEY) {
        const p = _prf(BigInt(req.body.prfIn));
        res.send(p.toString());
    } else {
        res.status(401);
    }
})

app.get('/pubkey', async (req, res) => {
    res.send({
        pubKey: getPubkey(process.env.HOLONYM_SECRET_EDDSA),
        pubKeyInSubgroup: getPubkeyTimes8(process.env.HOLONYM_SECRET_EDDSA)
    });
    // res.setTimeout(1500);
    
})

app.listen(port, () => {})
module.exports = {
    server: app,
    MAX_MSG: MAX_MSG, 
    ORDER_r: ORDER_r,
    ORDER_n: ORDER_n,
    SUBORDER: SUBORDER,
    MAX_MSG: MAX_MSG,
}