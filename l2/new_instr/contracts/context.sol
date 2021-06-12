pragma solidity >=0.4.0;

library EigenPriv {
    struct Context {
        string ctx_id;
        int32 version;
        mapping(bytes=>bytes) value;
    }

    // other functions
}
