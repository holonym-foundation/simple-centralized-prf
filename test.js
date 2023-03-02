const { expect, assert } = require("chai");
const {  createHmac } = require('crypto');
const request = require("supertest");
const { server, msg } = require("./index");
const ed = require('@noble/ed25519');
const { rejects } = require("assert");

describe("PRF Server", function() {
    before(async function() {
    });
    after(async function(){
        process.exit(0);
    })
    it("correct signature returns prf", async function(){
        const privKey = ed.utils.randomPrivateKey();
        const pubKey = await ed.getPublicKey(privKey);
    
        const sig = await ed.sign(Buffer.from(msg), privKey);

        const r = await request(server).post('/').send({
            pubkey: Buffer.from(pubKey).toString('hex'),//.replace('5','6'),
            sig: Buffer.from(sig).toString('hex')
        });

        // Simulate the PRF
        const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC); hmac.update(Buffer.from(pubKey).toString("hex")); 
        const shouldBe = (BigInt('0x'+hmac.digest('hex')) % 2736030358979909402780800718157159386076813972158567259200215660948447373041n).toString();
        expect(r.body.p).to.eq(shouldBe);
    });

    it("incorrect signature fails", async function(){
        const privKey = ed.utils.randomPrivateKey();
        const pubKey = await ed.getPublicKey(privKey);
    
        const sig = await ed.sign(Buffer.from(msg), privKey);

        const r = request(server).post('/').send({
            pubkey: Buffer.from(pubKey).toString('hex').replace('5','6'),
            sig: Buffer.from(sig).toString('hex')
        });

       await rejects(r);
    });


});

