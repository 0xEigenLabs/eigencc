# Assume libsdk_c.so is located in the current directory
export LD_LIBRARY_PATH=.

export TEESDK_METHOD="EigenTEERegister"
export TEESDK_ARGS=""
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

# Assume the compiled executable file named `teesdk_til`
pub_key=`./teesdk_util 2> /dev/null`

echo $pub_key

curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/store" -d "{\"digest\":\"1\", \"public_key\": \"$pub_key\"}"