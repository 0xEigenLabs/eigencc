import { stringify } from "querystring";
import { Sequelize, DataTypes } from "sequelize";
const sequelize = new Sequelize({
  dialect: "sqlite",

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  storage: "./db_recovery.sqlite",
});

const recoverydb = sequelize.define("recovery_st", {
  user_id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
  },
  total_shared_num: DataTypes.INTEGER,
  threshold: DataTypes.INTEGER,
  friends: DataTypes.STRING, // json string for array: [{user_id, email}]
});

sequelize
  .sync()
  .then(function () {
    return recoverydb.create({
      user_id: 1,
      total_shared_num: 1,
      threshold: 1,
      friends: JSON.stringify([{ user_id: 1, email: "a@b.com" }]),
    });
  })
  .then(function (row: any) {
    console.log(
      row.get({
        plain: true,
      })
    );
    recoverydb.destroy({ where: { user_id: row.user_id } });
  })
  .catch(function (err) {
    console.log("Unable to connect to the database:", err);
  });

const add = function (user_id, total_shared_num, threshold, friends) {
  return recoverydb.create({
    user_id,
    total_shared_num,
    threshold,
    friends,
  });
};

const findByID = function (user_id) {
  return recoverydb.findOne({ where: { user_id: user_id } });
};

const findAll = function () {
  return recoverydb.findAll();
};

const updateOrAdd = function (user_id, total_shared_num, threshold, friends) {
  recoverydb.findOne({ where: { user_id: user_id } }).then(function (row: any) {
    console.log(row);
    if (row === null) {
      add(user_id, total_shared_num, threshold, friends);
      return true;
    }
    return row
      .update({
        total_shared_num,
        threshold,
        friends,
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

export { updateOrAdd, findAll, findByID, add };
