const require_env_variables = (envVars) => {
  for (const envVar of envVars) {
    if (!process.env[envVar]) {
      throw new Error(`Error: set your '${envVar}' environmental variable `);
    }
  }
  console.log("Environmental variables properly set 👍");
};

const BaseResp = function (errno, message, data) {
  return { errno: errno, message: message, data: data };
};
const Succ = function (data) {
  return BaseResp(0, "", data);
};
const Err = function (errno, message) {
  return BaseResp(errno, message, "");
};

export enum ErrCode {
  Unknown = -1,
  Success = 0,
  InvalidAuth = 1,
}

const has_value = function (variable) {
  if (variable === undefined) {
    return false;
  }
  if (typeof variable === "string" && variable.trim() === "") {
    return false;
  }
  return true;
};

const check_user_id = function (req, user_id) {
  if (!has_value(user_id)) {
    console.log("user_id is not given!");
    return false;
  }

  if (process.env.DEBUG_MODE) {
    // Do not check the user_id and ensure return true if user_id exists
    return true;
  }

  if (!has_value(req.user)) {
    console.log("req.user does not exist, jwt is not used here?");
    return false;
  }

  if (req.user.user_id != user_id) {
    console.log(`expect ${req.user.user_id} but get ${user_id}`);
    return false;
  }

  return true;
};

export { BaseResp, Succ, Err, has_value, check_user_id, require_env_variables };
