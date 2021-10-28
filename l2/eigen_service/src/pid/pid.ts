import { Sequelize, DataTypes, Op } from "sequelize";

import * as util from "../util";
import * as friend_list from "../database_friend_relationship";

const sequelize = new Sequelize({
  dialect: "sqlite",
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  storage: "./db_user.sqlite",
});

export enum UserKind {
  GOOGLE,
}

const userdb = sequelize.define("user_st", {
  user_id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  kind: DataTypes.INTEGER, // 0: google, 1, twitter,,
  unique_id: DataTypes.STRING, // id from third-paty
  email: DataTypes.STRING,
  name: DataTypes.STRING,
  given_name: DataTypes.STRING,
  family_name: DataTypes.STRING,
  locale: DataTypes.STRING,
  verified_email: DataTypes.INTEGER, // 0 no, 1 yes
  picture: DataTypes.STRING,
  secret: DataTypes.STRING,
});

sequelize
  .sync()
  .then(function () {
    return userdb.create({
      kind: 0,
      unique_id: "1",
      email: "1@a.com",
      name: "eig",
      given_name: "1",
      family_name: "2",
      locale: "en-US",
      verified_email: 0,
      picture: "1",
      secret: "1",
    });
  })
  .then(function (row: any) {
    console.log(
      row.get({
        plain: true,
      })
    );
    userdb.destroy({ where: { user_id: row.user_id } });
  })
  .catch(function (err) {
    console.log("Unable to connect to the database:", err);
  });

const add = function (user_info) {
  return userdb.create(user_info);
};

const findAll = function () {
  return userdb.findAll();
};

const findByID = function (user_id: string) {
  return userdb
    .findOne({ where: { user_id: user_id } })
    .then(function (row: any) {
      console.log("yes", row);
      return row;
    });
};

const findByOpenID = function (id: string, kind: number) {
  return userdb
    .findOne({ where: { unique_id: id, kind: kind } })
    .then(function (row: any) {
      console.log(row);
      return row;
    });
};

const findByEmail = function (email: string) {
  return userdb.findOne({ where: { email: email } }).then(function (row: any) {
    console.log(row);
    return row;
  });
};

const updateOrAdd = function (user_id, new_info) {
  userdb.findOne({ where: { user_id: user_id } }).then(function (row: any) {
    console.log(row);
    if (row === null) {
      add(new_info);
      return true;
    }
    var concatenated = new Map([...row].concat([...new_info]));
    return row
      .update({
        concatenated,
      })
      .then(function (result) {
        console.log("Update success: " + result);
        return true;
      })
      .catch(function (err) {
        console.log("Update error: " + err);
        return false;
      });
  });
};

const findUsersInformation = function (ids) {
  return userdb.findAll({
    attributes: ["user_id", "email", "name"],
    where: {
      user_id: {
        [Op.in]: ids,
      },
    },
    raw: true,
  });
};

const findAllUserIDs = function () {
  return userdb
    .findAll({
      attributes: [["user_id", "user_id"]],
      raw: true,
    })
    .then(function (row: any) {
      console.log(row);
      if (row === null) {
        return new Set();
      }
      var users = new Set();
      for (let i = 0; i < row.length; i++) {
        users.add(row[i].user_id);
      }
      return users;
    })
    .catch(function (err) {
      console.log("Find error: " + err);
      return new Set();
    });
};

export {
  updateOrAdd,
  findAll,
  add,
  findByOpenID,
  findByID,
  findAllUserIDs,
  findUsersInformation,
  findByEmail,
};

module.exports = function (app) {
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
        if (!(await findByID(user_id))) {
          console.log("The user does not exist ", user_id);
          res.json(util.Err(-1, "user does not exist"));
          return;
        }
        var status = await friend_list.getStatusByUserId(user_id);
        var ids = new Set();
        var relationships = new Map();
        for (let i = 0; i < status.length; i++) {
          // There isn't status filter or filter the status
          if (
            filter_status === undefined ||
            filter_status == status[i].status
          ) {
            ids.add(status[i].user_id);
            relationships[status[i].user_id] = status[i].status;
          }
        }
        console.log(status, ids);
        var information_without_status: any = await findUsersInformation(
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
        if (!(await findByID(user_id))) {
          console.log("The user does not exist ", user_id);
          res.json(util.Err(-1, "user does not exist"));
          return;
        }
        var ids = await findAllUserIDs();
        var known = await friend_list.getKnownByUserId(user_id);
        var strangers = new Set([...ids].filter((x) => !known.has(x)));
        strangers.delete(Number(user_id));
        var result = Array.from(strangers);
        var information = await findUsersInformation(result);

        console.log(`Stranger list of ${user_id}: `, information);
        return res.json(util.Succ(information));
      default:
        res.json(util.Err(-1, "invalid action"));
        return;
    }
  });

  // get user by id
  app.get("/user/:user_id", async function (req, res) {
    const user_id = req.params.user_id;
    if (user_id === undefined) {
      res.json(util.Err(-1, "invalid argument"));
      return;
    }
    const result = await findByID(user_id);
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
      var responder = await findByEmail(responder_email);
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
        result = await add(req.body);
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
          !(await findByID(requester_id)) ||
          !(await findByID(responder_id))
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
          !(await findByID(requester_id)) ||
          !(await findByID(responder_id))
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
          !(await findByID(requester_id)) ||
          !(await findByID(responder_id))
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
          !(await findByID(requester_id)) ||
          !(await findByID(responder_id))
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
};
