export const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID ||
  "413535929013-us3b0rnd2l3uj85c17osktvv7e6o4o3t.apps.googleusercontent.com";
export const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || "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";

export const UI_ROOT_URI = "https://secret.ieigen.com/home";
export const SERVER_ROOT_URI = "https://rpc.ieigen.com/api";
export const JWT_SECRET = "import-secret-from-env"; //default hmac sha256

export const COOKIE_NAME = "auth_token";
export const TOTP_SECRET = "GAXGGYT2OU2DEOJR";
