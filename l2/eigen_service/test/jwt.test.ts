import { expect } from "chai";
import jsonwebtoken from "jsonwebtoken";

require("dotenv").config();

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

    const token = jsonwebtoken.sign(user_info, process.env.JWT_SECRET);
    console.log(token);
    const veri = jsonwebtoken.verify(token, process.env.JWT_SECRET);
    expect(veri.email).to.eq(user_info.email);

    const t =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJraW5kIjowLCJlbWFpbCI6InNreWVnYW8wODE3QGdtYWlsLmNvbSIsIm5hbWUiOiJTa3llIEdhbyIsImdpdmVuX25hbWUiOiJTa3llIiwiZmFtaWx5X25hbWUiOiJHYW8iLCJ1bmlxdWVfaWQiOiIxMTAzNDk0Mjg4OTU4MjMxMjgyODgiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUFUWEFKeE1INEVwVnNNbmNTVDNkTFZZWExNQ0dXZDJveXNrQkl5aFF5UE89czk2LWMiLCJsb2NhbGUiOiJ6aC1DTiIsInZlcmlmaWVkX2VtYWlsIjp0cnVlLCJzZWNyZXQiOiIiLCJ1c2VyX2lkIjo0LCJpYXQiOjE2MzU2MTMxMDh9.Mnj4xiSNnsWoinoE-UwivOlgqhgdHhM685cz9NoGyc0";
    const ccccc = jsonwebtoken.verify(t, process.env.JWT_SECRET);
    console.log(ccccc);
  });
});
