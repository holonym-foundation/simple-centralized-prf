const { expect } = require("chai");
const request = require("supertest");
const { server, msg } = require("./index");
const ed = require('@noble/ed25519');

describe("PRF Server", function() {
    before(async function() {
    });
    after(async function(){
        // process.exit(0);
    })
    it("abcaskdfjhas", async function(){
        // const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        const privKey = ed.utils.randomPrivateKey();
        const pubKey = await ed.getPublicKey(privKey);
        
        // console.log(Buffer.from(msg).toString('hex'));
        // let sig = await sign(null, Buffer.from('abc'), privateKey);

        const sig = await ed.sign(Buffer.from(msg), privKey);

        const r = await request(server).post('/').send({
            pubkey: Buffer.from(pubKey).toString('hex'),//.replace('5','6'),
            sig: Buffer.from(sig).toString('hex')
            // pubkey: publicKey.export({type: 'spki', format: 'der'}).toString('hex'),
            // sig: sig.toString('hex')
        });

       
    });


});

