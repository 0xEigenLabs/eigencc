'use strict';
const fs = require("fs");
const mimcjs = require("../../circomlib/src/mimc7.js");

let secret = "10";
const nullifierHash = mimcjs.hash(255, secret)

// root，paths2_root，paths2_root_pos could be stored on blockchain
// private: nullifierHash, leaf_index, secret

let rawdata = fs.readFileSync('/tmp/.nums.json');
let nums = JSON.parse(rawdata)

let leaf = mimcjs.hash(secret, "0");
let root = mimcjs.hash(leaf, nums[0]);

for (var i = 1; i < 8; i++) {
    root = mimcjs.hash(root, nums[i])
}

const inputs = {
    "root":root.toString(),
    "nullifierHash":nullifierHash.toString(),

    "secret": secret,
    "paths2_root": nums,
    "paths2_root_pos":[
    	1,
    	1,
    	1,
    	1,
    	1,
    	1,
    	1,
    	1
    ]
}

console.info(inputs)

fs.writeFileSync(
    "./input.json",
    JSON.stringify(inputs),
    "utf-8"
);

fs.writeFileSync(
    "./public.json",
    JSON.stringify([root.toString(), nullifierHash.toString()]),
    "utf-8"
);
