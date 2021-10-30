import * as sec from "../src/secretshare"
import * as mocha from 'mocha';
import {expect} from 'chai';

describe("secret share lib", () => {
    it("should be combine correctly", () => {
        let key = sec.generate_key()
        key = key.slice(2) // remove prefix 0x
        let shares = sec.split(key, sec.SecLevel.WEAK)
        console.log(shares)
        let comb = sec.combine(shares)
        console.log(key, comb)
        expect(comb).to.equal(key)
    })
})
