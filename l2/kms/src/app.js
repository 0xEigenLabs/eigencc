const express = require('express')
const log4js = require("./log");
var logger_ = log4js.logger("APP")
var db_ = require("./database.js")
var util = require("./util.js")

const app = express()
app.use(log4js.useLog());


var bodyParser_ = require('body-parser');
app.use(bodyParser_.json());

// query key
app.get('/stores', async function (req, res) {
    return res.json(util.Succ(await db_.findAll()))
})

app.get('/store', async function (req, res) {
    var digest = req.query.digest
    if (!util.has_value(digest)) {
        logger_.error("digest is empty")
        return res.json(util.Err(1, "digest missing"))
    }
    var result = await db_.findByDigest(digest);
    if (!result) {
        return res.json(util.Succ({}))
    }
    res.json(util.Succ(result))
})

// add new key
app.post("/store", async function (req, res) {
    var digest = req.body.digest;
    var pk = req.body.public_key;
    if (!util.has_value(digest) || !util.has_value(pk)) {
        return res.json(util.Err(1, "missing dig or pk"))
    }

    var result = db_.updateOrAdd(digest, digest, pk);
    res.json(util.Succ(result))
})

// update
app.put("/store", async function (req, res) {
    var old_digest = req.body.old_digest;
    var digest = req.body.digest;
    var pk = req.body.public_key;
    if (!util.has_value(digest) || !util.has_value(pk) ||
        !util.has_value(old_digest)) {
        return res.json(util.Err(1, "missing dig or pk"))
    }
    var result = db_.updateOrAdd(old_digest, digest, pk);
    res.json({"message": "ok", "data": result})
})

app.listen(3000, function() {
    console.log("KMS listening on port 3000!");
})
