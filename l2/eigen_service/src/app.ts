import express from "express";
import jwt from "express-jwt";
import { v4 as uuidv4 } from "uuid";
import * as log4js from "./log";
import * as db_pk from "./database_pk";
import * as db_txh from "./database_transaction_history";
import * as db_recovery from "./database_recovery";
import * as util from "./util";
import { Op } from "sequelize";
import url from "url";
const TOTP = require("totp.js");

import { JWT_SECRET, TOTP_SECRET } from "./login/config";

import cors from "cors";

import * as userdb from "./pid/pid";
import * as friend_list from "./database_friend_relationship";

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

// get user by id
app.get("/user/:user_id", async function (req, res) {
  const user_id = req.params.user_id;
  if (user_id === undefined) {
    res.json(util.Err(-1, "invalid argument"));
    return;
  }
  const result = await userdb.findByID(user_id);
  console.log(result);
  res.json(util.Succ(result));
});

// TODO: Refactor this function to make it clear
// create new user, send or confirm a friend request
app.post("/user", async function (req, res) {
  const action = req.body.action;
  const requester_id = req.body.requester_id;
  var responder_id = req.body.responder_id;
  const responder_email = req.body.responder_email;

  console.log(
    `${action} is going to do: ${requester_id}, ${responder_id} or ${responder_email}`
  );

  if (responder_id !== undefined && responder_email) {
    res.json(
      util.Err(
        -1,
        "responder_id and responder_email can not exist at the same time"
      )
    );
    return;
  }

  if (responder_email !== undefined) {
    var responder = await userdb.findByEmail(responder_email);
    if (responder) {
      responder_id = responder.user_id;
    } else {
      res.json(util.Err(-1, "responder_email do not exist in the database"));
      return;
    }
  }

  var result;

  switch (action) {
    case "new":
      // TODO: Remove this, just for test
      result = await userdb.add(req.body);
      console.log("Create a new user, id = ", result.user_id);
      console.log(result);
      return res.json(util.Succ(result));
    case "friend_request":
      if (requester_id === undefined || responder_id === undefined) {
        console.log(
          "Missing IDs when request or confirm friend.",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "missing IDs when request or confirm friend"));
        return;
      }

      if (
        !(await userdb.findByID(requester_id)) ||
        !(await userdb.findByID(responder_id))
      ) {
        console.log(
          "One of the users does not exist",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      result = await friend_list.request(requester_id, responder_id);
      if (result) {
        console.log("Send friend request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Send a friend request fail!");
        return res.json(util.Err(-1, "fail to send a friend request"));
      }

    case "friend_confirm":
      if (requester_id === undefined || responder_id === undefined) {
        console.log(
          "Missing IDs when request or confirm friend.",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "missing IDs when request or confirm friend"));
        return;
      }

      if (
        !(await userdb.findByID(requester_id)) ||
        !(await userdb.findByID(responder_id))
      ) {
        console.log(
          "One of the users does not exist",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      result = await friend_list.confirm(requester_id, responder_id);
      if (result) {
        console.log("Confirm a friend request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Confirm a friend request fail!");
        return res.json(util.Err(-1, "fail to confirm a friend request"));
      }
    case "friend_remove":
      if (requester_id === undefined || responder_id === undefined) {
        console.log(
          "Missing IDs when remove a friend.",
          requester_id,
          responder_id
        );
        result = await friend_list.remove(requester_id, responder_id);
        if (result) {
          console.log("Remove a friend success!");
          return res.json(util.Succ(result));
        } else {
          console.log("Remove a friend fail!");
          return res.json(util.Err(-1, "fail to remove friend"));
        }
      }

      if (
        !(await userdb.findByID(requester_id)) ||
        !(await userdb.findByID(responder_id))
      ) {
        console.log(
          "One of the users does not exist",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      result = await friend_list.remove(requester_id, responder_id);
      if (result) {
        console.log("Remove a friend request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Remove a friend fail!");
        return res.json(util.Err(-1, "fail to remove a friend"));
      }

    case "friend_reject":
      if (requester_id === undefined || responder_id === undefined) {
        console.log(
          "Missing IDs when reject friend.",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "missing IDs when reject friend"));
        return;
      }

      if (
        !(await userdb.findByID(requester_id)) ||
        !(await userdb.findByID(responder_id))
      ) {
        console.log(
          "One of the users does not exist",
          requester_id,
          responder_id
        );
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      result = await friend_list.reject(requester_id, responder_id);
      if (result) {
        console.log("Reject a friend request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Reject a friend fail!");
        return res.json(util.Err(-1, "fail to reject a friend request"));
      }

    default:
      res.json(util.Err(-1, "invalid action"));
      return;
  }
});

// get recovery data
app.get("/recovery", async function (req, res) {
  console.log(JSON.stringify(req.query));
  const user_id = req.query.user_id;

  if (user_id === undefined) {
    res.json(util.Err(-1, "missing user_id"));
    return;
  }
  const result = await db_recovery.findByID(user_id);
  console.log(result);
  res.json(util.Succ(result));
});

app.post("/recovery", async function (req, res) {
  console.log(JSON.stringify(req.body));
  const user_id = req.body.user_id;
  const total_shared_num = req.body.total_shared_num;
  const threshold = req.body.threshold;
  const friends = req.body.friends;

  if (user_id === undefined) {
    res.json(util.Err(-1, "missing user_id"));
    return;
  }
  const result = await db_recovery.updateOrAdd(
    user_id,
    total_shared_num,
    threshold,
    JSON.stringify(friends)
  );
  console.log(result);
  res.json(util.Succ(result));
});

// get friend list
app.get("/user", async function (req, res) {
  const action = req.query.action;

  switch (action) {
    case "friends":
      var user_id = req.query.user_id;
      var filter_status = req.query.status;
      if (filter_status !== undefined) {
        console.log("Filter the status of friends: ", filter_status);
      }
      if (user_id === undefined) {
        //res.json(util.Err(-1, "invalid argument"));
        var all_relationships = await friend_list.findAll();
        return res.json(util.Succ(all_relationships));
      }
      if (!(await userdb.findByID(user_id))) {
        console.log("The user does not exist ", user_id);
        res.json(util.Err(-1, "user does not exist"));
        return;
      }
      var status = await friend_list.getStatusByUserId(user_id);
      var ids = new Set();
      var relationships = new Map();
      for (let i = 0; i < status.length; i++) {
        // There isn't status filter or filter the status
        if (filter_status === undefined || filter_status == status[i].status) {
          ids.add(status[i].user_id);
          relationships[status[i].user_id] = status[i].status;
        }
      }
      console.log(status, ids);
      var information_without_status: any = await userdb.findUsersInformation(
        Array.from(ids)
      );
      console.log("Infomation without status: ", information_without_status);
      var information_with_status = new Array();
      for (let i = 0; i < information_without_status.length; i++) {
        information_with_status.push({
          user_id: information_without_status[i].user_id,
          email: information_without_status[i].email,
          name: information_without_status[i].name,
          status: relationships[information_without_status[i].user_id],
        });
      }
      console.log(`Friend list of ${user_id}: `, information_with_status);
      return res.json(util.Succ(information_with_status));
    case "strangers":
      var user_id = req.query.user_id;
      if (user_id === undefined) {
        res.json(util.Err(-1, "invalid argument"));
        return;
      }
      if (!(await userdb.findByID(user_id))) {
        console.log("The user does not exist ", user_id);
        res.json(util.Err(-1, "user does not exist"));
        return;
      }
      var ids = await userdb.findAllUserIDs();
      var known = await friend_list.getKnownByUserId(user_id);
      var strangers = new Set([...ids].filter((x) => !known.has(x)));
      strangers.delete(Number(user_id));
      var result = Array.from(strangers);
      var information = await userdb.findUsersInformation(result);

      console.log(`Stranger list of ${user_id}: `, information);
      return res.json(util.Succ(information));
    default:
      res.json(util.Err(-1, "invalid action"));
      return;
  }
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

const otpauthURL = function (options) {
  // unpack options
  var secret = options.secret;
  var label = options.label;
  var issuer = options.issuer;

  // validate required options
  if (!secret) throw new Error("Speakeasy - otpauthURL - Missing secret");
  if (!label) throw new Error("Speakeasy - otpauthURL - Missing label");

  // build query while validating
  var query: any = { secret: secret };
  if (issuer) query.issuer = issuer;

  // return url
  console.log(encodeURIComponent(label));
  return url.format({
    protocol: "otpauth",
    slashes: true,
    hostname: "otpt",
    pathname: encodeURIComponent(label),
    query: query,
  });
};

// get otpauth
app.get("/otpauth", async function (req, res) {
  const user_id = req.query.user_id;

  if (user_id === undefined) {
    console.log("Missing user id when request optauth");

    res.json(util.Err(-1, "missing user id when request optauth"));
    return;
  }
  const user = await userdb.findByID(user_id);
  if (user) {
    const key = TOTP_SECRET;
    const totp = new TOTP(key);
    const otpurl = `otpauth://totp/${user.email}?issuer=EigenNetwork&secret=${key}`;
    const test =
      "https://chart.googleapis.com/chart?chs=256x256&chld=L|0&cht=qr&chl=" +
      encodeURIComponent(otpauthURL({ secret: key, label: "EigenNetwork" }));
    console.log(test);
    res.json(util.Succ(otpurl));
    return;
  } else {
    console.log("User does not exist when request optauth");

    res.json(util.Err(-1, "user does not exist when request optauth"));
    return;
  }
});

// verify code
app.post("/otpauth", async function (req, res) {
  const user_id = req.body.user_id;
  const code = req.body.code;
  if (!util.has_value(user_id) || !util.has_value(code)) {
    return res.json(util.Err(1, "missing fields"));
  }
  console.log(req.body);
  const totp = new TOTP(TOTP_SECRET);
  var result = totp.verify(code);
  return res.json(util.Succ(result));
});

require("./login/google")(app);

app.listen(3000, function () {
  console.log("Eigen Service listening on port 3000!");
});
