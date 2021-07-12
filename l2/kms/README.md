# Simple KMS

```
nohup yarn start &

#query
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/store?digest=1"

#query all
curl -XGET -H "Content-Type:application/json"  --url "localhost:3000/stores"

# add
curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/store" -d '{"digest":"1", "public_key":"pk"}'
```
