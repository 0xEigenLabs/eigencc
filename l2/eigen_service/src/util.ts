const BaseResp = function(errno, message, data) {
    return {"errno": errno, "message": message, "data": data}
}
const Succ = function(data) {
    return BaseResp(0, "", data)
}
const Err = function(errno, message) {
    return BaseResp(errno, message, "")
}

const has_value = function(variable) {
    if (variable === undefined) {
        return false
    }
    if (typeof(variable) === 'string' && variable.trim() === "") {
        return false
    }
    return true
}

export {BaseResp, Succ, Err, has_value};
