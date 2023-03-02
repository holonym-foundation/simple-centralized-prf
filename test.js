const { expect, assert } = require("chai");
const { createHmac } = require('crypto');
const request = require("supertest");
const { server, msg } = require("./index");
const ed = require('@noble/ed25519');
const { rejects } = require("assert");

describe("PRF Server", function() {
    before(async function() {
        this.privKey = ed.utils.randomPrivateKey();
        this.pubKey = await ed.getPublicKey(this.privKey); 
        this.sig = await ed.sign(Buffer.from(msg), this.privKey);

        // Simulate the PRF
        const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC); 
        hmac.update(Buffer.from(this.pubKey).toString("hex")); 
        this.shouldBe = (BigInt('0x'+hmac.digest('hex')) % 2736030358979909402780800718157159386076813972158567259200215660948447373041n).toString();
    });
    after(async function(){
        // process.exit(0);
    })
    it("correct signature returns prf", async function(){
        const r = await request(server).post('/').send({
            pubkey: Buffer.from(this.pubKey).toString('hex'),//.replace('5','6'),
            sig: Buffer.from(this.sig).toString('hex')
        });

        expect(r.body.prf).to.eq(this.shouldBe);
    });

    it("incorrect signature fails", async function(){
        const r = request(server).post('/').send({
            pubkey: Buffer.from(this.pubKey).toString('hex').replace('5','6'),
            sig: Buffer.from(this.sig).toString('hex')
        });

       await rejects(r);
    });

    it("Authority can get PRF of any seed", async function(){
        const r = await request(server).post('/authority').send({
            input: Buffer.from(this.pubKey).toString('hex'),
            API_KEY: process.env.API_KEY
        });
        
        expect(r.text).to.eq(this.shouldBe);
    });

    it("Authority route doesn't work with bad API key", async function(){
        const r = request(server).post('/authority').send({
            pubkey: Buffer.from(this.pubKey).toString('hex'),
            sig: Buffer.from(this.sig).toString('hex')
        });
        await rejects(r);
    });


});

