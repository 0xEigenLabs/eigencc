exports.BaseResp = function(errno, message, data) {
    return {"errno": errno, "message": message, "data": data}
}
exports.Succ = function(data) {
    return exports.BaseResp(0, "", data)
}
exports.Err = function(errno, message) {
    return exports.BaseResp(errno, message, "")
}

exports.has_value = function(variable) {
    if (variable == undefined) {
        return false
    }
    if (variable.trim() == "") {
        return false
    }
    return true
}
