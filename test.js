const { expect } = require("chai");
const request = require("supertest");
const { server } = require("./index");
const bodyParser = require("body-parser");


describe("PRF Server", function() {
    before(async function() {
    });
    it("abcaskdfjhas", async function(){
        const r = await request(server).post('/').send({
            pubkey: "abc",
            sig: "abcd"
        });
        // console.log(r);
    });
    after(async function(){
        process.exit(0);
    })


});

