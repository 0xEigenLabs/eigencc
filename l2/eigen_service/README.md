# Eigen Service

- PKCS
- Transaction History
- Secret recovery

## Usage

### Compile

```
yarn && yarn build
yarn test
```

### Launch Server

```
forever start ./build/src/app.js  # or `yarn start` for dev
```

### PKCS

Simple local public key cache service on sqlite, with ecies inside.

```

#query
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/store?digest=1"

#query all
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/stores"

# add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/store" -d '{"digest":"1", "public_key":"pk"}' -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjowLCJlbWFpbCI6IkVpZ2VuTmV0d29ya0BnbWFpbC5jb20iLCJuYW1lIjoiRWlnZW4gTmV0V29yayIsImdpdmVuX25hbWUiOiJFaWdlbiBOZXRXb3JrIiwiZmFtaWx5X25hbWUiOiJFaWdlbiBOZXRXb3JrIiwicGljdHVyZSI6IiIsImxvY2FsZSI6IlNHIiwidmVyaWZpZWRfZW1haWwiOiJFaWdlbk5ldHdvcmtAZ21haWwuY29tIiwiaWF0IjoxNjM1NTgyMzI4fQ.F6zDTYVWm0I40hjchvPf4nZn56wIazunTXtUd-oFDaI"
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
# query
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?txid=1"

# search all (with/without filters)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&from=0x1"

# query all transactions with the reverse time order (also support page)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&order=1"

# query all transactions by page number
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search&page=1&page_size=10"

# query the count of all transactions on L2 (L2 -> L1, L2 -> L2)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?action=transaction_count_l2"

# query the count of all accounts on L2 ('from' on L2 -> L1, 'from' and 'to' on L2 -> L2)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txh?action=account_count_l2"

# add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/txh" -d '{"txid": "1", "from": "0x1", "to": "0x1", "type":0, "value": 1, "block_num": 1027, "name": "ERC20"}'

# update
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/txh/{txid}" -d '{"status": 1, "sub_txid": "2121"}'

# query all transactions on L2 (L1 -> L2 and L2 -> L1, with/witout filters, also support page and reverse order)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/txhs?action=search_l2&from=0x1&page=1&page_size=10&order=1"
```

### User Management

#### API

```
# Send a guardian request
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"guardian_id": 3}'

# Send a guardian request (or user email instead)
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"guardian_email": "a@b.com"}'

# Confirm a guardian request
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"action": "confirm", "guardian_id": 3}'

# Confirm a guardian request (or user email instead)
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"action": "confirm", "guardian_email": "a@b.com"}'

# Reject a guardian request
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"action": "reject", "guardian_id": 3}'

# Reject a guardian request (or user email instead)
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"action": "reject", "guardian_email": "a@b.com"}'

# Remove a guardian
curl -XDELETE -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"guardian_id": 3}'

# Remove a guardian
curl -XDELETE -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/guardian" -d '{"guardian_email": "a@b.com"}'

# Get guardians list
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}?action=guardians"
# Status:
#         1 mutual
#         2 waiting
#         3 confirming

# Get guardians list (We can filter the status, e.g., get only mutual status guardians)
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}?action=guardians&status=1"

# Get strangers list
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}" -d '{"action": "strangers"}'

# Save recovery data
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/recovery" -d '{"user_id": 2, "name": "recover_1", "desc": "NFT", "total_shared_num": 1, "threshold": 1, "friends": [{"user_id": 2, "email": "a@b.com"}, {"user_id": 3, "email": "c@d.com"}]}'

# Get recovery data
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/recovery?user_id=2"

# detele recovery
curl -XDELETE -H "Content-Type:application/json"  --url "localhost:3000/recovery"  -d '{"id": 6}'
```

### Login by Oauth

#### Google OAuth

1. Get google oauth url

```
curl http://localhost:3000/auth/google/url
```

2. Submit login request by copying the above url responsed to browser

3. Choose an account and authenticate the login request

4. Redirect the UI root url with jwt token

5. Access other backend API which need authorization with addtional header like:

```
 -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjExNDU1MDE2Njg5ODA0MTc1MTU3OSIsImVtYWlsIjoiaGliZHVhbkBnbWFpbC5jb20iLCJ2ZXJpZmllZF9lbWFpbCI6dHJ1ZSwibmFtZSI6IlN0ZXBoZW4iLCJnaXZlbl9uYW1lIjoiU3RlcGhlbiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS0vQU9oMTRHajJxZ2poczV6Qk15VzJ6Y0dUeEpyMG9FSmhiTkVaRmdnWm1xUXhEUT1zOTYtYyIsImxvY2FsZSI6InpoLUNOIiwiaWF0IjoxNjM0NDg3MjQyfQ.dkuRxjKyQNtUb2sZFvJ4RXW59p0D-0dhhYzkOjY4pYE"
```

#### Google Authenticator TOTP

```
# Save or update otpauth secret
curl -XPUT -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/otpauth" -d '{"secret": "GAXGGYT2OU2DEOJR"}'

# Verify code
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/user/{user_id}/otpauth" -d '{"code": "123456"}'

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
