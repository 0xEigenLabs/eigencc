var Sequelize = require("sequelize");
const { Op } = require("sequelize");

const sequelize = new Sequelize({
  dialect: "sqlite",

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  storage: "./db_transaction_history.sqlite",
});

const pkdb = sequelize.define("transaction_history_st", {
  txid: {
    type: Sequelize.STRING(64),
    allowNull: false,
    unique: true,
  },
  from: Sequelize.STRING,
  to: Sequelize.STRING,
  value: Sequelize.INTEGER,
  type: Sequelize.INTEGER,
  block_num: Sequelize.INTEGER,
  status: Sequelize.INTEGER,
  sub_txid: Sequelize.STRING,
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
      status: 0, // 1 success, 0 init
      sub_txid: "",
    });
  })
  .then(function (row) {
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

exports.add = function (dict) {
  return pkdb.create({
    txid: dict.txid,
    from: dict.from,
    to: dict.to,
    value: dict.value,
    type: dict.type,
    block_num: dict.block_num,
    status: dict.status || 0,
    sub_txid: dict.sub_txid || "",
  });
};

exports.getByTxid = function (txid) {
  return pkdb.findOne({ where: { txid: txid } });
};

exports.search = function (filter_dict, page, page_size, order) {
  console.log(filter_dict);
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
        total_page = Math.ceil(count / page_size);
        return {
          transactions: rows,
          total_page: total_page,
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
        total_page = Math.ceil(count / page_size);
        return {
          transactions: rows,
          total_page: total_page,
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

exports.findAll = function () {
  return pkdb.findAll();
};

exports.updateOrAdd = function (txid, update_dict) {
  pkdb.findOne({ where: { txid: txid } }).then(function (row) {
    if (row === null) {
      exports.add(update_dict);
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

exports.account_count_l2 = function () {
  return (async () => {
    l1_to_l2 = await pkdb.findAll({
      attributes: [["to", "account"]],
      where: {
        type: TX_TYPE_L1ToL2,
      },
    });

    s1 = new Set(l1_to_l2);

    l2_to_l1 = await pkdb.findAll({
      attributes: [["from", "account"]],
      where: {
        type: TX_TYPE_L2ToL1,
      },
    });

    s2 = new Set(l2_to_l1);

    l2_to_l2 = await pkdb.findAll({
      attributes: [
        ["from", "account"],
        ["to", "account"],
      ],
      where: {
        type: TX_TYPE_L2ToL2,
      },
    });

    s3 = new Set(l2_to_l2);

    return new Set([...s1, ...s2, ...s3]).size;
  })();
};

exports.transaction_count_l2 = function () {
  return pkdb.count({
    where: {
      type: {
        [Op.or]: [TX_TYPE_L1ToL2, TX_TYPE_L2ToL1, TX_TYPE_L2ToL2],
      },
    },
  });
};
