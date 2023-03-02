const { expect, should } = require("chai");
const {  createHmac } = require('crypto');
const request = require("supertest");
const { server, msg } = require("./index");
const ed = require('@noble/ed25519');

describe("PRF Server", function() {
    before(async function() {
    });
    after(async function(){
        // process.exit(0);
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
        const hmac = createHmac('sha256', process.env.HMAC_PRF_SECRET); hmac.update(Buffer.from(pubKey).toString("hex")); 
        const shouldBe = hmac.digest('hex');
        expect(r.text).to.eq(shouldBe)
    });


});

