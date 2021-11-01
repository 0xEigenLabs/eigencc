import express from "express";
import jsonwebtoken from "jsonwebtoken";
import axios from "axios";
import bodyParser from "body-parser";
import querystring from "querystring";
import * as crypto from "crypto";
import { Session } from "../session";

import * as util from "../util";
import * as userdb from "../pid/pid";
require("dotenv").config();

util.require_env_variables([
  "SERVER_ROOT_URI",
  "GOOGLE_CLIENT_ID",
  "JWT_SECRET",
  "GOOGLE_CLIENT_SECRET",
  "COOKIE_NAME",
  "UI_ROOT_URI",
]);

module.exports = function (app) {
  const redirectURI = "auth/google";

  function getGoogleAuthURL() {
    const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    const options = {
      redirect_uri: `${process.env.SERVER_ROOT_URI}/${redirectURI}`,
      client_id: process.env.GOOGLE_CLIENT_ID,
      access_type: "offline",
      response_type: "code",
      prompt: "consent",
      scope: [
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
      ].join(" "),
    };

    return `${rootUrl}?${querystring.stringify(options)}`;
  }

  // Getting login URL
  app.get("/auth/google/url", (req, res) => {
    return res.send(getGoogleAuthURL());
  });

  function getTokens({
    code,
    clientId,
    clientSecret,
    redirectUri,
  }: {
    code: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }): Promise<{
    access_token: string;
    expires_in: Number;
    refresh_token: string;
    scope: string;
    id_token: string;
  }> {
    /*
     * Uses the code to get tokens
     * that can be used to fetch the user's profile
     */
    const url = "https://oauth2.googleapis.com/token";
    const values = {
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    };

    console.log(values);
    return <any>axios
      .post(url, querystring.stringify(values), {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      })
      .then((res) => res.data)
      .catch((error) => {
        console.error(`Failed to fetch auth tokens`, error);
        throw new Error(error.message);
      });
  }
  // Getting the user from Google with the code
  app.get(`/${redirectURI}`, async (req, res) => {
    const code = req.query.code as string;
    console.log("res", req.query);
    const { id_token, access_token } = await getTokens({
      code,
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: `${process.env.SERVER_ROOT_URI}/${redirectURI}`,
    });
    console.log("token", id_token, access_token);

    // Fetch the user's profile with the access token and bearer
    const user: any = await axios
      .get(
        `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
        {
          headers: {
            Authorization: `Bearer ${id_token}`,
          },
        }
      )
      .then((res) => res.data)
      .catch((error) => {
        console.error(`Failed to fetch user`);
        throw new Error(error.message);
      });
    console.log("user", user);

    const exist_user: any = await userdb.findByOpenID(
      user.id,
      userdb.UserKind.GOOGLE
    );
    console.log("exist_user", exist_user);
    let user_info;
    if (exist_user === null) {
      //add to db
      user_info = {
        kind: userdb.UserKind.GOOGLE,
        email: user.email,
        name: user.name,
        given_name: user.given_name,
        family_name: user.family_name,
        unique_id: user.id,
        picture: user.picture,
        locale: user.locale,
        verified_email: user.verified_email,
        secret: "",
      };
      console.log(user_info);
      const result = await userdb.add(user_info);
      console.log("add", result);
    } else {
      user_info = {
        email: user.email || exist_user.email,
        name: user.name || exist_user.name,
        given_name: user.given_name || exist_user.given_name,
        family_name: user.family_name || exist_user.family_name,
        picture: user.picture || exist_user.picture,
        locale: user.locale || exist_user.locale,
        verified_email: user.verified_email || exist_user.verified_email,
      };
      const result = await userdb.updateOrAdd(exist_user.user_id, user_info);
      console.log("update", result);
    }

    const user_record: any = await userdb.findByOpenID(
      user.id,
      userdb.UserKind.GOOGLE
    );

    user_info.user_id = user_record.user_id;

    const token = jsonwebtoken.sign(user_info, process.env.JWT_SECRET);
    console.log("user cookie", token);

    /*
    res.cookie(COOKIE_NAME, token, {
      maxAge: 900,
      httpOnly: true,
      secure: false,
      domain: "ieigen.com",
      //path: '/',
      sameSite: 'Lax',
    });
   */

    console.log("user record: ", user_record);

    let hash = crypto.createHash("sha256");
    let hashcode = hash.update(token).digest("hex");
    console.log(hashcode);
    Session.add_token(hashcode, new Session.session(token, 600));
    res.redirect(
      `${process.env.UI_ROOT_URI}?id=${user_record.user_id}&${process.env.COOKIE_NAME}=${hashcode}`
    );
  });
};
