//SPDX-License-Identifier: Apache-2
pragma solidity ^0.6.11;

// import "arb-shared-dependencies/contracts/ArbSys.sol";
import "../../arbos/builtin/ArbSys.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./RLPEncode.sol";
import "solidity-rlp/contracts/RLPReader.sol";

/**
 * @title EigenCallLibrary
 * @dev A simple EigenCall library which wraps all operators
 * @author Weber
 *
 */
library EigenCallLibrary {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    using Strings for uint256;

    /*
     * Private functions
     */

    /**
     * @dev Decode a RLP encoded bytes into bytes
     * @param rlp_encoded The RLP encoded bytes
     * @return Raw bytes.
     */
    function _rlp_decode_as_bytes(bytes memory rlp_encoded) private pure returns (bytes memory) {
        return rlp_encoded.toRlpItem().toBytes();
    }

    /**
     * @dev `eigenCall` wrapper
     * @param op The operator we want to do
     * @param arg1 The 1st argument of operator
     * @param arg2 The 2nd argument of operator, leave empty if unused
     * @param arg3 The 3rd argument of operator, leave empty if unused
     * @return The operator result
     */
    function _call_eigen_call(
        bytes memory op,
        bytes memory arg1,
        bytes memory arg2,
        bytes memory arg3
    ) private pure returns (bytes memory) {
        // TODO: Now we use RLP encoding in `ecall`, it'd be better using `abi.encode`
        //       to save gas
        bytes[] memory list;

        list = new bytes[](4);

        list[0] = RLPEncode.encodeBytes(op);
        list[1] = RLPEncode.encodeBytes(arg1);
        list[2] = RLPEncode.encodeBytes(arg2);
        list[3] = RLPEncode.encodeBytes(arg3);
        bytes memory input = RLPEncode.encodeList(list);

        bytes memory result = ArbSys(address(100)).eigenCall(input);
        require(
            _compare_bytes(result, RLPEncode.encodeBytes("")) != true,
            "Eigencall returns an empty string which means we encounter error"
        );
        return _rlp_decode_as_bytes(result);
    }

    /**
     * @dev Compare the equalization of 2 bytes
     * @param a bytes a
     * @param b bytes b
     * @return true if they are equal, otherwise false
     */
    function _compare_bytes(bytes memory a, bytes memory b) private pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    /*
     * Public functions
     */

    /**
     * @dev Encrypt a plain number
     * @param plain The number we want to encrypt
     * @return The cipher.
     */
    function encrypt(uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("encrypt1", bytes(plain.toString()), "", "");
    }

    /**
     * @dev Decrypt a cipher
     * @param cipher The cipher we want to decrypt
     * @return The decrypted number, which is ascii string
     */
    function decrypt(bytes memory cipher) public pure returns (bytes memory) {
        return _call_eigen_call("decrypt1", cipher, "", "");
    }

    /**
     * @dev Add 2 ciphers
     * @param cipher1 The first cipher
     * @param cipher2 The second cipher
     * @return The decrypted result.
     */
    function addCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return _call_eigen_call("add_cipher_cipher2", cipher1, cipher2, "");
    }

    /**
     * @dev Add a cipher to a plain number
     * @param cipher The cipher
     * @param plain The plain number
     * @return The decrypted result.
     */
    function addCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("add_cipher_plain2", cipher, bytes(plain.toString()), "");
    }

    /**
     * @dev Substract a cipher with a cipher
     * @param cipher1 The cipher of minuend
     * @param cipher2 The cipher of subtrahend
     * @return The decrypted result.
     */
    function subCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        return _call_eigen_call("sub_cipher_cipher2", cipher1, cipher2, "");
    }

    /**
     * @dev Substract a cipher with a plain number
     * @param cipher The cipher of minuend
     * @param plain The plain number of subtrahend
     * @return The decrypted result.
     */
    function subCipherPlain(bytes memory cipher, uint256 plain) public pure returns (bytes memory) {
        return _call_eigen_call("sub_cipher_plain2", cipher, bytes(plain.toString()), "");
    }

    /**
     * @dev Compare a cipher with a cipher
     * @param cipher1 The 1st cipher
     * @param cipher2 The 2nd cipher
     * @return The compare result, -1 if cipher1 < cipher2, 1 if cipher1 > cipher2, 0 if they are equal
     */
    function compareCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (int256)
    {
        bytes memory compare_result = _call_eigen_call(
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

    /**
     * @dev Compare a cipher with a plain number
     * @param cipher The cipher
     * @param plain The plain number
     * @return The compare result, -1 if cipher < plain, 1 if cipher > plain, 0 if they are equal
     */
    function compareCipherPlain(bytes memory cipher, uint256 plain) public pure returns (int256) {
        bytes memory compare_result = _call_eigen_call(
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

    /**
     * @dev Re-encrypt a cipher with a secret
     * @param secret The secret we want to use to re-encrypt
     * @param cipher The cipher number
     * @return The decrypted result.
     */
    function reEncrypt(bytes memory secret, bytes memory cipher)
        public
        pure
        returns (bytes memory)
    {
        return _call_eigen_call("re_encrypt2", secret, cipher, "");
    }

    /**
     * @dev A utility function which is used for copying bytes
     * @param src The source bytes we want to copy
     * @return A new bytes which are equal to src
     */
    function copyBytes(bytes memory src) public pure returns (bytes memory) {
        bytes memory copy = new bytes(src.length);
        uint256 max = src.length + 31;
        for (uint256 i = 32; i <= max; i += 32) {
            assembly {
                mstore(add(copy, i), mload(add(src, i)))
            }
        }
        return copy;
    }
}
