import { Sequelize, Op, DataTypes } from "sequelize";

const sequelize = new Sequelize({
  dialect: "sqlite",

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  storage: "./db_friend_relationship.sqlite",
});

const NOT_FRIENDS = 0x0;
const PENDING_FIRST_SECOND = 0x1;
const PENDING_SECOND_FIRST = 0x2;
const FRIENDS = 0x3;
const BLOCK_FIRST_SECOND = 0x4;
const BLOCK_SECOND_FIRST = 0x5;
const BLOCK_BOTH = 0x6;

const friend_relationship_table = sequelize.define("friend_relationship_st", {
  user_first_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true,
  },
  user_second_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true,
  },
  type: DataTypes.INTEGER,
});

sequelize
  .sync()
  .then(function () {
    return friend_relationship_table.create({
      user_first_id: 1,
      user_second_id: 2,
      type: NOT_FRIENDS,
    });
  })
  .then(function (row: any) {
    console.log(
      row.get({
        plain: true,
      })
    );
    friend_relationship_table.destroy({
      where: {
        user_first_id: row.user_first_id,
        user_second_id: row.user_second_id,
      },
    });
  })
  .catch(function (err) {
    console.log("Unable to connect to the database:", err);
  });

const addFriendRequest = function (requester_id, responder_id) {
  if (requester_id < responder_id) {
    return friend_relationship_table.create({
      user_first_id: requester_id,
      user_second_id: responder_id,
      type: PENDING_FIRST_SECOND,
    });
  } else if (requester_id > responder_id) {
    return friend_relationship_table.create({
      user_first_id: responder_id,
      user_second_id: requester_id,
      type: PENDING_SECOND_FIRST,
    });
  } else {
    // Do nothing
    return false;
  }
};

const confirmFriendRequest = function (requester_id, responder_id) {
  if (requester_id < responder_id) {
    friend_relationship_table
      .findOne({
        where: { user_first_id: requester_id, user_second_id: responder_id },
      })
      .then(function (row: any) {
        if (row === null) {
          console.log(
            "User: ",
            requester_id,
            " has not sent request to ",
            responder_id
          );
          return false;
        }

        if (row.type === PENDING_FIRST_SECOND) {
          return row
            .update({
              type: FRIENDS,
            })
            .then(function (result) {
              console.log("Update success: " + result);
              return true;
            })
            .catch(function (err) {
              console.log("Update error: " + err);
              return false;
            });
        } else {
          console.log(
            "User: ",
            requester_id,
            " has not sent request to ",
            responder_id,
            " and the relationship between them is ",
            row.type
          );
          return false;
        }
      });
  } else if (requester_id > responder_id) {
    friend_relationship_table
      .findOne({
        where: { user_first_id: responder_id, user_second_id: requester_id },
      })
      .then(function (row: any) {
        if (row === null) {
          console.log(
            "User: ",
            requester_id,
            " has not sent request to ",
            responder_id
          );
          return false;
        }

        if (row.type === PENDING_SECOND_FIRST) {
          return row
            .update({
              type: FRIENDS,
            })
            .then(function (result) {
              console.log("Update success: " + result);
              return true;
            })
            .catch(function (err) {
              console.log("Update error: " + err);
              return false;
            });
        } else {
          console.log(
            "User: ",
            requester_id,
            " has not sent request to ",
            responder_id,
            " and the relationship between them is ",
            row.type
          );
          return false;
        }
      });
  } else {
    // Do nothing
    return false;
  }
};

// TODO: Add functions to remove friend, block user

const getFriendListByUserId = function (user_id) {
  return friend_relationship_table.findAll({
    where: {
      [Op.or]: [{ user_first_id: user_id }, { user_second_id: user_id }],
      type: FRIENDS,
    },
  });
};

export { addFriendRequest, confirmFriendRequest, getFriendListByUserId };
