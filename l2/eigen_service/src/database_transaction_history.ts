import {Sequelize, Op, DataTypes} from "sequelize";

const sequelize = new Sequelize({
  dialect: "sqlite",

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  storage: "./data/db_transaction_history.sqlite",
});

const pkdb = sequelize.define("transaction_history_st", {
  txid: {
    type: DataTypes.STRING(64),
    allowNull: false,
    unique: true,
  },
  from: DataTypes.STRING,
  to: DataTypes.STRING,
  name: DataTypes.STRING,
  value: DataTypes.INTEGER,
  type: DataTypes.INTEGER,
  block_num: DataTypes.INTEGER,
  status: DataTypes.INTEGER,
  sub_txid: DataTypes.STRING,
});

const TX_TYPE_L1ToL1 = 0x0;
const TX_TYPE_L1ToL2 = 0x1;
const TX_TYPE_L2ToL1 = 0x2;
const TX_TYPE_L2ToL2 = 0x3;

sequelize
  .sync()
  .then(function () {
    return pkdb.create({
      txid: "_txid",
      from: "0xID",
      to: "0xID",
      value: 0,
      type: TX_TYPE_L1ToL1,
      block_num: 0,
      name: "ETH",
      status: 0, // 1 success, 0 init
      sub_txid: "",
    });
  })
  .then(function (row: any) {
    console.log(
      row.get({
        plain: true,
      })
    );
    pkdb.destroy({ where: { txid: row.txid } });
  })
  .catch(function (err) {
    console.log("Unable to connect to the database:", err);
  });

const add = function (dict) {
  return pkdb.create({
    txid: dict.txid,
    from: dict.from,
    to: dict.to,
    value: dict.value,
    type: dict.type,
    name: dict.name || "ETH",
    block_num: dict.block_num || -1, // `block_num` can be empty when `send` is called
    status: dict.status || 0,
    sub_txid: dict.sub_txid || "",
  });
};

const getByTxid = function (txid) {
  return pkdb.findOne({ where: { txid } });
};

const search = function (filter_dict, page, page_size, order) {
  console.log(filter_dict);
  filter_dict.type = {
        [Op.or]: filter_dict.type
  }
  if (page) {
    console.log("page = ", page);
    console.log("page_size = ", page_size);
    if (order) {
      console.log("Reverse order is enabled");
      return (async () => {
        const { count, rows } = await pkdb.findAndCountAll({
          where: filter_dict,
          order: [["updatedAt", "DESC"]],
          limit: page_size,
          offset: (page - 1) * page_size,
        });
        console.log("count = ", count);
        console.log("rows = ", rows);
        const total_page = Math.ceil(count / page_size);
        return {
          transactions: rows,
          total_page,
        };
      })();
    } else {
      return (async () => {
        const { count, rows } = await pkdb.findAndCountAll({
          where: filter_dict,
          limit: page_size,
          offset: (page - 1) * page_size,
        });
        console.log("count = ", count);
        console.log("transactions = ", rows);
        const total_page = Math.ceil(count / page_size);
        return {
          transactions: rows,
          total_page,
        };
      })();
    }
  } else {
    if (order) {
      console.log("Reverse order is enabled");
      return pkdb.findAll({
        where: filter_dict,
        order: [["updatedAt", "DESC"]],
      });
    } else {
      return pkdb.findAll({
        where: filter_dict,
      });
    }
  }
};

const findAll = function () {
  return pkdb.findAll();
};

const updateOrAdd = function (txid, update_dict) {
  pkdb.findOne({ where: { txid } }).then(function (row: any) {
    if (row === null) {
      add(update_dict);
      return true;
    }
    return row
      .update({
        status: update_dict.status || 0,
        sub_txid: update_dict.sub_txid || "",
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

const account_count_l2 = function () {
  return (async () => {
    const l2_to_l1:any = await pkdb.findAll({
      attributes: [["from", "account"]],
      where: {
        type: TX_TYPE_L2ToL1,
      },
      raw: true,
    });
    console.log(l2_to_l1);
    const accounts = new Set();
    for (let i = 0; i < l2_to_l1.length; i++) {
      accounts.add(l2_to_l1[i].account);
    }

    const l2_to_l2:any = await pkdb.findAll({
      attributes: [
        ["from", "account"],
        ["to", "account"],
      ],
      where: {
        type: TX_TYPE_L2ToL2,
      },
      raw: true,
    });

    console.log(l2_to_l2);
    for (let i = 0; i < l2_to_l2.length; i++) {
      accounts.add(l2_to_l2[i].account);
    }

    return accounts.size;
  })();
};

const transaction_count_l2 = function () {
  return pkdb.count({
    where: {
      type: {
        [Op.or]: [TX_TYPE_L2ToL1, TX_TYPE_L2ToL2],
      },
    },
  });
};
export {account_count_l2, transaction_count_l2, updateOrAdd, add, search, getByTxid, findAll};
