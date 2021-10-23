import { Sequelize, DataTypes } from "sequelize";
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

export { updateOrAdd, findAll, add, findByOpenID, findByID };
