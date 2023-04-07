const Bitcoin = require("./Bitcoin.js");

const privateKey = Buffer.from("85333564a2720a7b7350c4efe85331e75434576ec5e72ea051a976e62709b9ba", "hex");
Bitcoin.displayAll(privateKey);