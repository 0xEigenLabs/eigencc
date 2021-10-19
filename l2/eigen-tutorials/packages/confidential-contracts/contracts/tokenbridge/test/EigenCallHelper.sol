//SPDX-License-Identifier: Apache-2
pragma solidity ^0.6.11;

import "./RLPEncode.sol";
import "solidity-rlp/contracts/RLPReader.sol";
import "../../arbos/builtin/ArbSys.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

library EigenCallHelper {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using Strings for uint256;

    function _rlp_decode_as_bytes(bytes memory rlp_encoded) private pure returns (bytes memory) {
        return rlp_encoded.toRlpItem().toBytes();
    }

    function execute (
        bytes memory arg1,
        bytes memory arg2,
        bytes memory arg3,
        bytes memory arg4
    ) public pure returns (bytes memory) {
        // TODO: Now we use RLP encoding in `ecall`, it'd be better using `abi.encode`
        //       to save gas
        bytes[] memory list;

        list = new bytes[](4);

        list[0] = RLPEncode.encodeBytes(arg1);
        list[1] = RLPEncode.encodeBytes(arg2);
        list[2] = RLPEncode.encodeBytes(arg3);
        list[3] = RLPEncode.encodeBytes(arg4);
        bytes memory input = RLPEncode.encodeList(list);

        bytes memory result = ArbSys(address(100)).eigenCall(input);
        require(_compare_bytes(result, RLPEncode.encodeBytes("")) != true, "Eigencall returns an empty string which means we encounter error" );
        return _rlp_decode_as_bytes(result);
    }
    
    function re_encrypt(bytes memory cipher_key, bytes memory cipher) public view returns (bytes memory) {
        bytes memory result = execute("re_encrypt2", cipher_key, cipher, "");
        return _rlp_decode_as_bytes(result);
    }

    function addCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return execute("add_cipher_cipher2", cipher1, cipher2, "");
    }

    function addCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return execute("add_cipher_plain2", cipher, bytes(plain.toString()), "");
    }

    function subCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return execute("sub_cipher_cipher2", cipher1, cipher2, "");
    }

    function subCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return execute("sub_cipher_plain2", cipher, bytes(plain.toString()), "");
    }

    function _compare_bytes(bytes memory a, bytes memory b) private pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    function compareCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (int256)
    {
        bytes memory compare_result = execute(
            "compare_cipher_cipher2",
            cipher1,
            cipher2,
            ""
        );
        require(
            _compare_bytes(compare_result, "0") ||
                _compare_bytes(compare_result, "1") ||
                _compare_bytes(compare_result, "-1"),
            "compare result can only be -1, 0, or 1"
        );

        if (_compare_bytes(compare_result, "-1")) {
            return -1;
        } else if (_compare_bytes(compare_result, "1")) {
            return 1;
        } else {
            return 0;
        }
    }

    function compareCipherPlain(bytes memory cipher, uint256 plain) public pure returns (int256) {
        bytes memory compare_result = execute(
            "compare_cipher_plain2",
            cipher,
            bytes(plain.toString()),
            ""
        );
        require(
            _compare_bytes(compare_result, "0") ||
                _compare_bytes(compare_result, "1") ||
                _compare_bytes(compare_result, "-1"),
            "compare result can only be -1, 0, or 1"
        );

        if (_compare_bytes(compare_result, "-1")) {
            return -1;
        } else if (_compare_bytes(compare_result, "1")) {
            return 1;
        } else {
            return 0;
        }
    }

    function copy_bytes(bytes memory _bytes) public pure returns (bytes memory) {
        bytes memory copy = new bytes(_bytes.length);
        uint256 max = _bytes.length + 31;
        for (uint256 i = 32; i <= max; i += 32) {
            assembly {
                mstore(add(copy, i), mload(add(_bytes, i)))
            }
        }
        return copy;
    }
}
