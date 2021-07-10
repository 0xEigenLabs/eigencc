
const mimcGenContract = require("../../circomlib/src/mimc_gencontract.js");


const SEED = "mimc";


async function gen () {
   var data = mimcGenContract.createCode(SEED, 91)

   console.info(data.toString())
}

gen()


