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
  storage: "./data/db_recovery.sqlite",
});

const recoverydb = sequelize.define("recovery_st", {
  user_id: DataTypes.INTEGER,
  name: DataTypes.STRING,
  desc: DataTypes.STRING,
  total_shared_num: DataTypes.INTEGER,
  threshold: DataTypes.INTEGER,
  friends: DataTypes.STRING, // json string for array: [{user_id, email}]
});

sequelize
  .sync()
  .then(function () {
    return recoverydb.create({
      user_id: 1,
      name: "name",
      desc: "desc",
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
    recoverydb.destroy({ where: { id: row.id } });
  })
  .catch(function (err) {
    console.log("Unable to connect to the database:", err);
  });

const add = function (user_id, name, desc, total_shared_num, threshold, friends) {
  return recoverydb.create({
    user_id,
    name,
    desc,
    total_shared_num,
    threshold,
    friends,
  });
};

const findByUserID = function (user_id) {
  return recoverydb.findAll({ where: { user_id: user_id } });
};

const remove = function (id) {
    return recoverydb.destroy({ where: { id: id } });
};

const updateOrAdd = function (user_id, name, desc, total_shared_num, threshold, friends) {
  recoverydb.findOne({ where: { user_id: user_id } }).then(function (row: any) {
    console.log(row);
    if (row === null) {
      add(user_id, name, desc, total_shared_num, threshold, friends);
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

export { updateOrAdd, remove, findByUserID, add };
