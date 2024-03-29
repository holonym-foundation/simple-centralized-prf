const { expect, assert } = require("chai");
const {  createHmac, createHash, randomBytes } = require('crypto');
const request = require("supertest");
const { server, msg, MAX_MSG, ORDER_r } = require("./index");
// const ed = require('@noble/ed25519');
const { rejects } = require("assert");

describe("PRF Server", function() {
    before(async function() {
        // this.privKey = ed.utils.randomPrivateKey();
        // this.pubKey = await ed.getPublicKey(this.privKey); 
        // this.sig = await ed.sign(Buffer.from(msg), this.privKey);
        this.preimage = randomBytes(64).toString('hex');
        const hash = createHash('sha512'); 
        hash.update(this.preimage); 
        this.digest = hash.digest('hex');
        this.digestFr = (BigInt('0x'+this.digest) % ORDER_r)
        // Simulate the PRF
        const hmac = createHmac('sha512', process.env.HOLONYM_SECRET_HMAC); 
        hmac.update(this.digestFr.toString(16)); 
        this.shouldBe = (BigInt('0x'+hmac.digest('hex')) % MAX_MSG).toString();
    });
    after(async function(){
        // process.exit(0);
    })
    it("correct signature returns prf", async function(){
        const r = await request(server).post('/').send({
            preimage: this.preimage,
            digestFr: this.digestFr.toString(),//.replace('5','6'),
        });

        expect(r.body.prfOut).to.eq(this.shouldBe);
    });

    it("incorrect signature fails", async function(){
        const r = request(server).post('/').send({
            preimage: this.preimage,
            digestFr: this.digestFr.toString().replace('5','6'),
        });

       await rejects(r);
    });

    it("Authority can get PRF of any seed", async function(){
        const r = await request(server).post('/authority').send({
            prfIn: this.digestFr.toString(),
            API_KEY: process.env.API_KEY
        });
        
        expect(r.text).to.eq(this.shouldBe);
    });

    it("Authority route doesn't work with bad API key", async function(){
        const r = request(server).post('/authority').send({
            input: Buffer.from(this.digest).toString('hex'),
            API_KEY: process.env.API_KEY + "69"
        });
        await rejects(r);
    });


});

