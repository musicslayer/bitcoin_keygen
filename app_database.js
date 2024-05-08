const RocksDB = require("./RocksDB.js");

// Replace with the path to the folder where you would like to create the database
let dbPath = "C:\\MyFolder\\DB";

// Replace with the path to the text file listing all funded bitcoin addresses
let addressPath = "C:\\MyFolder\\Bitcoin_addresses_LATEST.txt";

// Create the database
(async () => await RocksDB.createFromFile(dbPath, addressPath))();