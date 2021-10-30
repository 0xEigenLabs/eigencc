import { Sequelize, DataTypes, Op } from "sequelize";
import jwt from "express-jwt";
const TOTP = require("totp.js");

import * as util from "../util";
import * as friend_list from "../database_friend_relationship";

import { JWT_SECRET } from "../login/config";

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

const updateSecret = function (user_id, secret) {
  return userdb.findOne({ where: { user_id } }).then(function (row: any) {
    if (row === null) {
      console.log("Update error: User does not exist");
      return false;
    }
    return row
      .update({
        secret: secret,
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
  // get user, his/her friends, his/her strangers by id
  app.get(
    "/user/:user_id",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
    async function (req, res) {
      const user_id = req.params.user_id;
      if (user_id === undefined) {
        res.json(util.Err(-1, "invalid argument"));
        return;
      }
      const action = req.body.action;

      if (action === undefined) {
        const result = await findByID(user_id);
        console.log(result);
        res.json(util.Succ(result));
        return;
      }

      switch (action) {
        case "guardians":
          var filter_status = req.query.status;
          if (filter_status !== undefined) {
            console.log("Filter the status of guardians: ", filter_status);
          }
          if (user_id === undefined) {
            //res.json(util.Err(-1, "invalid argument"));
            var all_relationships = await friend_list.findAll();
            res.json(util.Succ(all_relationships));
            return;
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
          console.log(
            "Infomation without status: ",
            information_without_status
          );
          var information_with_status = new Array();
          for (let i = 0; i < information_without_status.length; i++) {
            information_with_status.push({
              user_id: information_without_status[i].user_id,
              email: information_without_status[i].email,
              name: information_without_status[i].name,
              status: relationships[information_without_status[i].user_id],
            });
          }
          console.log(`Guardian list of ${user_id}: `, information_with_status);
          res.json(util.Succ(information_with_status));
          return;
        case "strangers":
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
          res.json(util.Succ(information));
          return;
        default:
          res.json(util.Err(-1, "invalid action"));
          return;
      }
    }
  );

  // TODO: Just for test
  app.post(
    "/user",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
    async function (req, res) {
      var result: any = await add(req.body);
      console.log("Create a new user, id = ", result.user_id);
      console.log(result);
      return res.json(util.Succ(result));
    }
  );

  // Guardian add
  app.post(
    "/user/:user_id/guardian",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
    async function (req, res) {
      const user_id = req.params.user_id;
      var guardian_id = req.body.guardian_id;
      if (!util.has_value(user_id)) {
        res.json(util.Err(-1, "missing user_id"));
        return;
      }

      console.log(`User ${user_id} wants add guardian`);
      const guardian_email = req.body.guardian_email;

      if (guardian_id !== undefined && guardian_email) {
        res.json(
          util.Err(
            -1,
            "guardian_id and guardian_email can not exist at the same time"
          )
        );
        return;
      }

      if (util.has_value(guardian_email)) {
        var guardian = await findByEmail(guardian_email);
        if (guardian) {
          guardian_id = guardian.user_id;
        } else {
          res.json(util.Err(-1, "guardian_email do not exist in the database"));
          return;
        }
      }

      if (!util.has_value(guardian_id)) {
        res.json(
          util.Err(-1, "miss guardian_id or guardian_email is not found")
        );
        return;
      }

      if (!(await findByID(user_id)) || !(await findByID(guardian_id))) {
        console.log("One of the users does not exist", user_id, guardian_id);
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      // NOTE: When send a friend requet, self is requester, guardian is responder
      const result = await friend_list.request(user_id, guardian_id);
      if (result) {
        console.log("Send guardian request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Send a guardian request fail!");
        return res.json(util.Err(-1, "fail to send a guardian request"));
      }
    }
  );

  // Guardian confirm or reject
  app.put(
    "/user/:user_id/guardian",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
    async function (req, res) {
      const user_id = req.params.user_id;
      const action = req.body.action;
      var guardian_id = req.body.guardian_id;
      if (!util.has_value(user_id) || !util.has_value(action)) {
        res.json(util.Err(-1, "missing user_id or action"));
        return;
      }

      console.log(`User ${user_id} wants do ${action}`);
      const guardian_email = req.body.guardian_email;

      console.log(
        `${action} is going to do: ${user_id}, ${guardian_id} or ${guardian_email}`
      );

      if (guardian_id !== undefined && guardian_email) {
        res.json(
          util.Err(
            -1,
            "guardian_id and guardian_email can not exist at the same time"
          )
        );
        return;
      }

      if (util.has_value(guardian_email)) {
        var guardian = await findByEmail(guardian_email);
        if (guardian) {
          guardian_id = guardian.user_id;
        } else {
          res.json(util.Err(-1, "guardian_email do not exist in the database"));
          return;
        }
      }

      if (!util.has_value(guardian_id)) {
        res.json(
          util.Err(-1, "miss guardian_id or guardian_email is not found")
        );
        return;
      }

      if (!(await findByID(user_id)) || !(await findByID(guardian_id))) {
        console.log("One of the users does not exist", user_id, guardian_id);
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      var result;
      switch (action) {
        case "confirm":
          // NOTE: When send a guardian confirm, self is responder, guardian is requester
          result = await friend_list.confirm(guardian_id, user_id);
          if (result) {
            console.log("Confirm a guardian request success!");
            return res.json(util.Succ(result));
          } else {
            console.log("Confirm a guardian request fail!");
            return res.json(util.Err(-1, "fail to confirm a guardian request"));
          }
        case "reject":
          // NOTE: When send a guardian reject, self is responder, guardian is requester
          result = await friend_list.reject(guardian_id, user_id);
          if (result) {
            console.log("Reject a guardian request success!");
            return res.json(util.Succ(result));
          } else {
            console.log("Reject a guardian fail!");
            return res.json(util.Err(-1, "fail to reject a guardian request"));
          }
        default:
          res.json(util.Err(-1, "invalid action"));
          return;
      }
    }
  );

  // Guardian add
  app.delete(
    "/user/:user_id/guardian",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] }),
    async function (req, res) {
      const user_id = req.params.user_id;
      var guardian_id = req.body.guardian_id;
      if (!util.has_value(user_id)) {
        res.json(util.Err(-1, "missing user_id"));
        return;
      }

      console.log(`User ${user_id} wants delete guardian`);
      const guardian_email = req.body.guardian_email;

      if (guardian_id !== undefined && guardian_email) {
        res.json(
          util.Err(
            -1,
            "guardian_id and guardian_email can not exist at the same time"
          )
        );
        return;
      }

      if (util.has_value(guardian_email)) {
        var guardian = await findByEmail(guardian_email);
        if (guardian) {
          guardian_id = guardian.user_id;
        } else {
          res.json(util.Err(-1, "guardian_email do not exist in the database"));
          return;
        }
      }

      if (!util.has_value(guardian_id)) {
        res.json(
          util.Err(-1, "miss guardian_id or guardian_email is not found")
        );
        return;
      }

      if (!(await findByID(user_id)) || !(await findByID(guardian_id))) {
        console.log("One of the users does not exist", user_id, guardian_id);
        res.json(util.Err(-1, "one of the users does not exist"));
        return;
      }

      const result = await friend_list.remove(user_id, guardian_id);
      if (result) {
        console.log("Remove a guardian request success!");
        return res.json(util.Succ(result));
      } else {
        console.log("Remove a guardian fail!");
        return res.json(util.Err(-1, "fail to remove a guardian"));
      }
    }
  );

  app.put(
    "/user/:user_id/otpauth",
    // jwt({ secret: JWT_SECRET, algorithms: ["HS256"] },
    async function (req, res) {
      const user_id = req.params.user_id;
      const secret = req.body.secret;
      if (!util.has_value(user_id) || !util.has_value(secret)) {
        res.json(util.Err(-1, "missing user_id or secret"));
        return;
      }

      const result = await updateSecret(user_id, secret);

      if (result) {
        console.log("Save a otpauth secret success!");
        res.json(util.Succ(result));
        return;
      } else {
        console.log("Save a otpauth secret fail!");
        res.json(util.Err(-1, "fail to save a otpauth secret"));
        return;
      }
    }
  );

  // verify code
  app.get("/user/:user_id/otpauth", async function (req, res) {
    const user_id = req.params.user_id;
    const code = req.body.code;
    if (!util.has_value(user_id) || !util.has_value(code)) {
      return res.json(util.Err(1, "missing fields"));
    }
    console.log(req.body);
    const user = await findByID(user_id);
    if (user) {
      if (user.secret) {
        const totp = new TOTP(user.secret);
        var result = totp.verify(code);
        res.json(util.Succ(result));
        return;
      } else {
        console.log("The secret does not exist ", user_id);
        res.json(util.Err(-1, "secret does not exist"));
        return;
      }
    } else {
      console.log("The user does not exist ", user_id);
      res.json(util.Err(-1, "user does not exist"));
      return;
    }
  });
};
