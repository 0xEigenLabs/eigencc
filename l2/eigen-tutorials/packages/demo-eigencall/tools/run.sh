set -e
set -x
# Assume libsdk_c.so is located in the current directory
basedir=$(cd "$(dirname "$0")"; pwd)
cd $basedir

# Set TEESDK related parameters here
export TEESDK_METHOD=EigenTEERegister
export TEESDK_ARGS=
export TEESDK_UID=uid
export TEESDK_TOKEN=token
export TEESDK_AUDITOR_BASE_DIR=/app/release/services/auditors
export TEESDK_AUDITOR_NAME=godzilla
export TEESDK_ENCLAVE_INFO_PATH=/app/release/services/enclave_info.toml
export SDK_LIB=/app/release/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${SDK_LIB}

gcc teesdk_util.c -I. -L${SDK_LIB} -lsdk_c -o teesdk_util
# Assume the compiled executable file named `teesdk_til`

./teesdk_util
pub_key=`./teesdk_util 2> /dev/null`

echo $pub_key

curl -XPOST -H "Content-Type:application/json"  --url "host.docker.internal:3000/store" -d "{\"digest\":\"1\", \"public_key\": \"$pub_key\"}"
