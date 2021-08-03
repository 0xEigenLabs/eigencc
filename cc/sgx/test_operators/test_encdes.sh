export LD_LIBRARY_PATH=.

#######################################################
# TEST `enc` and `dec`
num=123

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

decrypt=`./test_teesdk 2> /dev/null`


export TEESDK_METHOD="operator"
export TEESDK_ARGS="dec,1,$decrypt"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_num=`./test_teesdk 2> /dev/null`

if [ $num -ne $result_num ]; then
    echo "Test fail! exit"
    exit 24
fi
########################################################


#######################################################
# TEST `add`
num1=123
num2=231
((expect=num1+num2))

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num1}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op1=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num2}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op2=`./test_teesdk 2> /dev/null`


export TEESDK_METHOD="operator"
export TEESDK_ARGS="add,2,$cipher_op1,$cipher_op2"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_cipher=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="dec,1,$result_cipher"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_num=`./test_teesdk 2> /dev/null`

if [ $expect -ne $result_num ]; then
    echo "Test fail! exit"
    exit 66
fi
#######################################################

#######################################################
# TEST `sub`
num1=100
num2=1
((expect=num1-num2))

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num1}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op1=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num2}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op2=`./test_teesdk 2> /dev/null`


export TEESDK_METHOD="operator"
export TEESDK_ARGS="sub,2,$cipher_op1,$cipher_op2"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_cipher=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="dec,1,$result_cipher"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_num=`./test_teesdk 2> /dev/null`

if [ $expect -ne $result_num ]; then
    echo "Test fail! exit"
    exit 107
fi
#######################################################

#######################################################
# TEST `add1`
num1=123
num2=231
((expect=num1+num2))

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num1}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op1=`./test_teesdk 2> /dev/null`


export TEESDK_METHOD="operator"
export TEESDK_ARGS="add1,2,$cipher_op1,$num2"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_cipher=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="dec,1,$result_cipher"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_num=`./test_teesdk 2> /dev/null`

if [ $expect -ne $result_num ]; then
    echo "Test fail! exit"
    exit 141
fi
#######################################################


#######################################################
# TEST `sub1`
num1=100
num2=1
((expect=num1-num2))

export TEESDK_METHOD="operator"
export TEESDK_ARGS="enc,1,${num1}"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

cipher_op1=`./test_teesdk 2> /dev/null`


export TEESDK_METHOD="operator"
export TEESDK_ARGS="sub1,2,$cipher_op1,$num2"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_cipher=`./test_teesdk 2> /dev/null`

export TEESDK_METHOD="operator"
export TEESDK_ARGS="dec,1,$result_cipher"
export TEESDK_UID="uid"
export TEESDK_TOKEN= "token"

result_num=`./test_teesdk 2> /dev/null`

if [ $expect -ne $result_num ]; then
    echo "Test fail! exit"
    exit 176
fi
#######################################################