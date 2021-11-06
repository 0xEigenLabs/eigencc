pragma solidity ^0.6.11;

import "./EigenCallLibrary.sol";

contract EigenCallLibraryUseDemo {
    function demo_encrypt(uint256 plain) public pure returns (bytes memory) {
        bytes memory output = EigenCallLibrary.encrypt(plain);
        return output;
    }

    function demo_decrypt(bytes memory cipher) public pure returns (bytes memory) {
        bytes memory output = EigenCallLibrary.decrypt(cipher);

        return output;
    }

    function demo_addCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.addCipherCipher(cipher1, cipher2);
        return output;
    }

    function demo_addCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.addCipherPlain(cipher, plain);
        return output;
    }

    function demo_subCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.subCipherCipher(cipher1, cipher2);
        return output;
    }

    function demo_subCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (bytes memory)
    {
        bytes memory output = EigenCallLibrary.subCipherPlain(cipher, plain);
        return output;
    }

    function demo_compareCipherCipher(bytes memory cipher1, bytes memory cipher2)
        public
        pure
        returns (int256)
    {
        int256 result = EigenCallLibrary.compareCipherCipher(cipher1, cipher2);
        return result;
    }

    function demo_compareCipherPlain(bytes memory cipher, uint256 plain)
        public
        pure
        returns (int256)
    {
        int256 result = EigenCallLibrary.compareCipherPlain(cipher, plain);
        return result;
    }
}
