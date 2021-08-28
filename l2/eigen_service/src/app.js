const express = require('express')
const log4js = require("./log");
var logger = log4js.logger("APP")
var db_pk = require("./database_pk")
var db_txh = require("./database_transaction_history")
var util = require("./util.js")

const app = express()
app.use(log4js.useLog());


var bodyParser = require('body-parser');
app.use(bodyParser.json());

// query key
app.get('/stores', async function (req, res) {
    return res.json(util.Succ(await db_pk.findAll()))
})

app.get('/store', async function (req, res) {
    var digest = req.query.digest
    if (!util.has_value(digest)) {
        logger.error("digest is empty")
        return res.json(util.Err(1, "digest missing"))
    }
    var result = await db_pk.findByDigest(digest);
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

    var result = db_pk.updateOrAdd(digest, digest, pk);
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
    var result = db_pk.updateOrAdd(old_digest, digest, pk);
    res.json(util.Succ(result))
})

/*
app.get("/txhs", async function(req, res) {
    return res.json(util.Succ(await db_txh.findAll()))
})
*/

//TODO: retrieve by page
app.get("/txhs", async function(req, res) {
    var action = req.query.action
    console.log(req.query)
    if (action != "search") {
        return res.json(util.Err(1, "invalid action"))
    }
    let dict = req.query
    delete dict['action']
    return res.json(util.Succ(await db_txh.search(req.query)))
})

app.get("/txh", async function(req, res) {
    var txid = req.query.txid
    if (!util.has_value(txid)) {
        logger.error("txid is empty")
        return res.json(util.Err(1, "txid missing"))
    }
    var result = await db_txh.getByTxid(txid);
    if (!result) {
        return res.json(util.Succ({}))
    }
    res.json(util.Succ(result))
})

// add new key
app.post("/txh", async function (req, res) {
    var txid = req.body.txid;
    var from = req.body.from;
    var to = req.body.to;
    var value = req.body.value;
    var type = req.body.type;
    if (!util.has_value(txid) ||
        !util.has_value(from) ||
        !util.has_value(value) ||
        !util.has_value(to) ||
        !util.has_value(type)) {
        return res.json(util.Err(1, "missing fields"))
    }
    console.log(req.body);

    var result = db_txh.updateOrAdd(txid, {
        "txid": txid,
        "from": from,
        "to": to,
        "value": value,
        "type": Number(type),
        "status": req.body.status || 0,
        "sub_txid": req.body.sub_txid || ''
    });
    res.json(util.Succ(result))
})

// update
app.put("/txh/:txid", async function (req, res) {
    var txid = req.params.txid;
    if (!util.has_value(txid)) {
        return res.json(util.Err(1, "missing fields"))
    }
    var result = db_txh.updateOrAdd(txid, {
        "status": req.body.status || 0,
        "sub_txid": req.body.sub_txid || ''
    });
    res.json(util.Succ(result))
})

app.listen(3000, function() {
    console.log("Eigen Service listening on port 3000!");
})
