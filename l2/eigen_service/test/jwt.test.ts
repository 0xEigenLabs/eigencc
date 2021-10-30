import { expect } from "chai";
import jsonwebtoken from "jsonwebtoken";

import { JWT_SECRET } from "../src/login/config";

describe("JWT token generate", () => {
  it("should generate correctly", () => {
    const user_info = {
      user_id: 0,
      email: "EigenNetwork@gmail.com",
      name: "Eigen NetWork",
      given_name: "Eigen NetWork",
      family_name: "Eigen NetWork",
      picture: "",
      locale: "SG",
      verified_email: "EigenNetwork@gmail.com",
    };

    const token = jsonwebtoken.sign(user_info, JWT_SECRET);
    console.log(token);
    expect(token).not(null);
  });
});
