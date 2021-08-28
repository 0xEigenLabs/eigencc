var Sequelize = require('sequelize');
const sequelize = new Sequelize({
  dialect: 'sqlite',

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  storage: './db_transaction_history.sqlite'
});

const pkdb = sequelize.define('transaction_history_st', {
  txid: Sequelize.STRING(64),
  from: Sequelize.STRING,
  to: Sequelize.STRING,
  value: Sequelize.INTEGER,
  type: Sequelize.INTEGER,
  status: Sequelize.INTEGER,
  sub_txid: Sequelize.STRING
});

const TX_TYPE_L1ToL1 = 0x0
const TX_TYPE_L1ToL2 = 0x1
const TX_TYPE_L2ToL1 = 0x2
const TX_TYPE_L2ToL2 = 0x3

sequelize.sync().then(function() {
    return pkdb.create({
        txid: "_txid",
        from: "0xID",
        to: "0xID",
        value: 0,
        type: TX_TYPE_L1ToL1,
        status: 0, // 1 success, 0 init
        sub_txid: ''
    });
}).then(function(row) {
    console.log(row.get({
        plain: true
    }));
    pkdb.destroy({where:{txid: row.txid}})
}).catch(function (err) {
  console.log('Unable to connect to the database:', err);
});

exports.add = function(dict) {
  return pkdb.create({
    txid: dict.txid,
    from: dict.from,
    to: dict.to,
    value: dict.value,
    type: dict.type,
    status: dict.status || 0,
    sub_txid: dict.sub_txid || ''
  })
};

exports.getByTxid = function(txid) {
  return pkdb.findOne({where: {txid: txid}})
};

exports.search = function(filter_dict) {
  console.log(filter_dict)
  return pkdb.findAll({where: filter_dict})
};

exports.findAll = function() {
    return pkdb.findAll();
}

exports.updateOrAdd = function(txid, update_dict){
    pkdb.findOne({where: {txid: txid
    }}).then(function(row){
        if (row === null) {
            exports.add(update_dict)
            return true
        }
        return row.update({
            status: update_dict.status || 0,
            sub_txid: update_dict.sub_txid || ''
        }).then(function(result){
            console.log("Update success: "+result);
            return true
        }).catch(function(err){
            console.log("Update error: "+err);
            return false
        });
    });
};
