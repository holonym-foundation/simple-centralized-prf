const {  createHmac } = require('crypto');
const ed = require('@noble/ed25519');
const express = require('express');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
const port = 3000;
const msg = 'DO NOT SIGN THIS UNLESS YOU ARE ON https://holonym.id';

const _prf = input => {
    const hmac = createHmac('sha256', process.env.HMAC_PRF_SECRET);
    hmac.update(input); 
    return hmac.digest('hex');
}

// Signs the ephemeral "pubkey" given as prfSeed, and signature is used as easy-to-code proof of discrete log
const authorizedPRF = async (pubkey, sig) => {
    if(await _verify(pubkey,sig)) {
        return _prf(pubkey);
    } else {
        throw 'Error verifying knowledge of discrete log (in this case, via ECDSA signature)';
    }
}

const _verify = async (pubkey, sig) => {
    // const verify = createVerify(null);
    // verify.update();
    // verify.end();
    // return verify.verify(pubkey, sig);
    // console.log("verifu", await ed.verify(sig, Buffer.from(msg), pubkey));
    
    // For some reason, bad inputs cause the promise to never reject. Timeout instead to avoid this minor bug:
//     console.log("this was called")
//     const result = Promise.race([
//         ed.verify(sig, Buffer.from(msg), pubkey),
//         new Promise(function(resolve, reject){
//             console.log(Object.keys(resolve))
//         })
//     ]);
//     console.log("rrrr", await result);
//    return result;
    return await ed.verify(sig, Buffer.from(msg), pubkey)
//    return await ed.verify(sig, Buffer.from(msg), pubkey);
}


/* ****************** */

app.post('/', async (req, res) => {
    res.setTimeout(1000);
    console.log("body", req.body)
  res.send(await authorizedPRF(req.body.pubkey, req.body.sig));
})

app.listen(port, () => {})
module.exports = {
    server: app,
    msg: msg
}