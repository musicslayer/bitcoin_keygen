const Bitcoin = require("./Bitcoin.js");

// Replace with the private key you wish to examine
const privateKeyHex = "55c8c38eb853501d2c73359a60e9081eaf5acb25bbd9da3c974f3ae6ce149520";

const privateKey = Buffer.from(privateKeyHex, "hex");
Bitcoin.displayAll(privateKey);