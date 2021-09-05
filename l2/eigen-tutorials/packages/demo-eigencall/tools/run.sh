# Assume libsdk_c.so is located in the current directory
export LD_LIBRARY_PATH=../../../../../cc/sgx/release/lib

source "../.env"

# Assume the compiled executable file named `teesdk_til`
pub_key=`./teesdk_util 2> /dev/null`

echo $pub_key

curl -XPOST -H "Content-Type:application/json"  --url "localhost:3000/store" -d "{\"digest\":\"1\", \"public_key\": \"$pub_key\"}"
