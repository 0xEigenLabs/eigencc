require("dotenv").config();

const requireEnvVariables = (envVars) => {
  for (const envVar of envVars) {
    if (!process.env[envVar]) {
      throw new Error(`Error: set your '${envVar}' environmental variable `);
    }
  }
  console.log("Environmental variables properly set 👍");
};

requireEnvVariables([
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "UI_ROOT_URI",
  "SERVER_ROOT_URI",
  "JWT_SECRET",
  "COOKIE_NAME",
]);

export const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
export const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
export const UI_ROOT_URI = process.env.UI_ROOT_URI;
export const SERVER_ROOT_URI = process.env.SERVER_ROOT_URI;
export const JWT_SECRET = process.env.JWT_SECRET;
export const COOKIE_NAME = process.env.COOKIE_NAME;
export const DEBUG_MODE = process.env.DEBUG_MODE || false;
