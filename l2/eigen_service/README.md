# Eigen Service

- PKCS
- Transaction History

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

- status： status of the transaction, 0: new, 1: confirmed, 2. only for withdraw, confirmed in Layer 1
- type: transaction type

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

#search all (with/without filters)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&from=0x1"

#query all transactions with the reverse time order (also support page)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&order=1"

#query all transactions by page number
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&page=1&page_size=10"

#query the count of all transactions on L2 (L2 -> L1, L2 -> L2)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?action=transaction_count_l2"

#query the count of all accounts on L2 ('from' on L2 -> L1, 'from' and 'to' on L2 -> L2)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?action=account_count_l2"

#add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/txh" -d '{"txid": "1", "from": "0x1", "to": "0x1", "type":0, "value": 1, "block_num": 1027}'

#update
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/txh/{txid}" -d '{"status": 1, "sub_txid": "2121"}'

#query all transactions on L2 (L1 -> L2 and L2 -> L1, with/witout filters, also support page and reverse order)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search_l2&from=0x1&page=1&page_size=10&order=1"
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
