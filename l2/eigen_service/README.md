# Eigen Service
* PKCS
* Transaction History

## Test
`yarn test`

## Usage

### Launch Server
```
forever start ./src/app.js  # or `yarn start` for dev
```

### PKCS
Simple local public key cache service on sqlite, with ecies inside.

```

#query
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/store?digest=1"

#query all
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/stores"

# add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/store" -d '{"digest":"1", "public_key":"pk"}'
```
### Transaction History

#### Data type 
* status： status of the transaction, 0: new, 1: confirmed, 2.  only for withdraw, confirmed in Layer 1
* type: transaction type

```
const TX_TYPE_L1ToL1 = 0x0
const TX_TYPE_L1ToL2 = 0x1
const TX_TYPE_L2ToL1 = 0x2
const TX_TYPE_L2ToL2 = 0x3
```

#### API

```
#query
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?txid=1"
#search all
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&from=0x1"
#add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/txh" -d '{"txid": "1", "from": "0x1", "to": "0x1", "type":0, "value": 1}'
#update
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/txh/{txid}" -d '{"status": 1, "sub_txid": "2121"}'
```

## Deployment in production

### Build
```
docker build -t ieigen/service:v1 .
```

### Run
```
docker run --name=eigen-service -p 3000:3000 -d ieigen/service:v1
```

