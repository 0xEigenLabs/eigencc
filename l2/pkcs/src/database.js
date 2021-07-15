var Sequelize = require('sequelize');
const sequelize = new Sequelize({
  dialect: 'sqlite',

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  storage: './db.sqlite'
});

const pkdb = sequelize.define('pk_st', {
  digest: Sequelize.STRING(64),
  public_key: Sequelize.STRING
});

sequelize.sync().then(function() {
    return pkdb.create({
        digest: 'eigen__',
        public_key: 'eigne__'
    });
}).then(function(row) {
    console.log(row.get({
        plain: true
    }));
    pkdb.destroy({where:{digest: row.digest}})
}).catch(function (err) {
  console.log('Unable to connect to the database:', err);
});

exports.add = function(digest, pk) {
  return pkdb.create({
      digest: digest,
      public_key: pk
  })
};

exports.findByDigest = function(dig) {
  return pkdb.findOne({where: {digest: dig}})
};

exports.findAll = function() {
    return pkdb.findAll();
}

exports.updateOrAdd = function(old_dig, new_dig, new_pk){
    pkdb.findOne({where: {digest: old_dig
    }}).then(function(row){
        console.log(row)
        if (row === null) {
            exports.add(new_dig, new_pk)
            return true
        }
        return row.update({
            digest: new_dig,
            public_key: new_pk
        }).then(function(result){
            console.log("Update success: "+result);
            return true
        }).catch(function(err){
            console.log("Update error: "+err);
            return false
        });
    });
};
