import express from "express";
import jwt from "express-jwt";
import { v4 as uuidv4 } from "uuid";
import * as log4js from "./log";
import * as db_pk from "./database_pk";
import * as db_txh from "./database_transaction_history";
import * as db_recovery from "./database_recovery";
import * as util from "./util";
import url from "url";

import { JWT_SECRET, TOTP_SECRET } from "./login/config";

import cors from "cors";

import * as userdb from "./pid/pid";

import bodyParser from "body-parser";
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

const logger = log4js.logger("Eigen");
app.use(log4js.useLog());
const issueOptions = {
  origin: true,
  credentials: true,
};

app.use(cors(issueOptions));

// query key
app.get("/stores", async function (req, res) {
  return res.json(util.Succ(await db_pk.findAll()));
});

app.get("/store", async function (req, res) {
  const digest = req.query.digest;
  if (!util.has_value(digest)) {
    logger.error("digest is empty");
    return res.json(util.Err(1, "digest missing"));
  }
  const result = await db_pk.findByDigest(digest);
  if (!result) {
    return res.json(util.Succ({}));
  }
  res.json(util.Succ(result));
});

// add new key
app.post(
  "/store",
  //jwt({ secret: JWT_SECRET, algorithms: ['HS256'] }),
  async function (req, res) {
    const digest = req.body.digest;
    const pk = req.body.public_key;
    if (!util.has_value(digest) || !util.has_value(pk)) {
      return res.json(util.Err(1, "missing dig or pk"));
    }

    const result = db_pk.updateOrAdd(digest, digest, pk);
    res.json(util.Succ(result));
  }
);

// update
app.put("/store", async function (req, res) {
  const old_digest = req.body.old_digest;
  const digest = req.body.digest;
  const pk = req.body.public_key;
  if (
    !util.has_value(digest) ||
    !util.has_value(pk) ||
    !util.has_value(old_digest)
  ) {
    return res.json(util.Err(1, "missing dig or pk"));
  }
  const result = db_pk.updateOrAdd(old_digest, digest, pk);
  res.json(util.Succ(result));
});

/*
app.get("/txhs", async function(req, res) {
    return res.json(util.Succ(await db_txh.findAll()))
})
*/

// get recovery data
app.get("/recovery", async function (req, res) {
  console.log(JSON.stringify(req.query));
  const user_id = req.query.user_id;

  if (user_id === undefined) {
    res.json(util.Err(-1, "missing user_id"));
    return;
  }
  const result = await db_recovery.findByUserID(user_id);
  console.log(result);
  res.json(util.Succ(result));
});

// get recovery data
app.delete("/recovery", async function (req, res) {
  console.log(JSON.stringify(req.query));
  const id = req.body.id;

  if (id === undefined) {
    res.json(util.Err(-1, "missing user_id"));
    return;
  }
  const result = await db_recovery.remove(id);
  console.log(result);
  res.json(util.Succ(result));
});

app.post("/recovery", async function (req, res) {
  console.log(JSON.stringify(req.body));
  const user_id = req.body.user_id;
  const name = req.body.name;
  const desc = req.body.desc;
  const total_shared_num = req.body.total_shared_num;
  const threshold = req.body.threshold;
  const friends = req.body.friends;

  if (user_id === undefined) {
    res.json(util.Err(-1, "missing user_id"));
    return;
  }
  const result = await db_recovery.add(
    user_id,
    name,
    desc,
    total_shared_num,
    threshold,
    JSON.stringify(friends)
  );
  console.log(result);
  res.json(util.Succ(result));
});

app.get("/txhs", async function (req, res) {
  const action = req.query.action;
  console.log(req.query);
  const dict = req.query;

  const page = dict.page;
  const page_size = dict.page_size;
  const order = dict.order;
  switch (action) {
    case "search":
      delete dict.action;
      delete dict.page;
      delete dict.page_size;
      delete dict.order;
      return res.json(
        util.Succ(await db_txh.search(req.query, page, page_size, order))
      );
      break;
    case "search_l2":
      delete dict.action;
      delete dict.page;
      delete dict.page_size;
      delete dict.order;

      // TODO: 0x2 (L2->L1), 0x3 (L2->L2) should replaced with enum
      /*
      dict.type = {
        [Op.or]: [0x2, 0x3],
      };
      */
      dict.type = ["2", "3"];
      return res.json(
        util.Succ(await db_txh.search(req.query, page, page_size, order))
      );
      break;

    default:
      return res.json(util.Err(1, "invalid action"));
      break;
  }
});

app.get("/txh", async function (req, res) {
  const action = req.query.action;
  console.log("action = ", action);
  if (!action) {
    const txid = req.query.txid;
    if (!util.has_value(txid)) {
      logger.error("txid is empty");
      return res.json(util.Err(1, "txid missing"));
    }
    const result = await db_txh.getByTxid(txid);
    if (!result) {
      return res.json(util.Succ({}));
    }
    res.json(util.Succ(result));
  } else {
    switch (action) {
      case "transaction_count_l2":
        return res.json(util.Succ(await db_txh.transaction_count_l2()));
        break;
      case "account_count_l2":
        return res.json(util.Succ(await db_txh.account_count_l2()));
        break;
      default:
        return res.json(util.Err(1, "invalid action"));
        break;
    }
  }
});

// add transaction
app.post(
  "/txh",
  jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
  async function (req, res) {
    const txid = req.body.txid;
    const from = req.body.from;
    const to = req.body.to;
    const value = req.body.value;
    const block_num = req.body.block_num;
    const type = req.body.type;
    const name = req.body.name;
    if (
      !util.has_value(txid) ||
      !util.has_value(from) ||
      !util.has_value(value) ||
      !util.has_value(to) ||
      !util.has_value(type)
    ) {
      return res.json(util.Err(1, "missing fields"));
    }
    console.log(req.body);

    const result = db_txh.updateOrAdd(txid, {
      txid,
      from,
      to,
      value,
      type: Number(type),
      name: name || "ETH",
      block_num: req.body.block_num || -1,
      status: req.body.status || 0,
      sub_txid: req.body.sub_txid || "",
    });
    res.json(util.Succ(result));
  }
);

// update transaction status
app.put("/txh/:txid", async function (req, res) {
  const txid = req.params.txid;
  if (!util.has_value(txid)) {
    return res.json(util.Err(1, "missing fields"));
  }
  const result = db_txh.updateOrAdd(txid, {
    status: req.body.status || 0,
    sub_txid: req.body.sub_txid || "",
  });
  res.json(util.Succ(result));
});

require("./login/google")(app);
require("./pid/pid")(app);

app.listen(3000, function () {
  console.log("Eigen Service listening on port 3000!");
});
