const fs = require('fs');
const readline = require('readline');
const rocksdb = require("rocksdb");

class RocksDB {
    db;

    static async createFromFile(dbpath, filepath) {
        return new Promise(async (resolve, reject) => {
            try {
                let rocksdb = new RocksDB(dbpath);
                await rocksdb.open();

                const rl = readline.createInterface({
                    input: fs.createReadStream(filepath, {encoding: "utf8"}),
                    crlfDelay: Infinity
                });
    
                rl.on('line', async (line) => {
                    await rocksdb.put(line, 0);
                });
    
                rl.on('close', () => {
                    resolve();
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }

    constructor(dbpath) {
        this.db = new rocksdb(dbpath);
    }

    async open(options) {
        return new Promise((resolve, reject) => {
            try {
                this.db.open(options, (err) => {
                    if(err) {
                        reject(err);
                    }
                    else {
                        resolve();
                    }
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }
    
    async put(key, value, options) {
        return new Promise((resolve, reject) => {
            try {
                this.db.put(key, value, options, (err) => {
                    if(err) {
                        reject(err);
                    }
                    else {
                        resolve();
                    }
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }
    
    async get(key, options) {
        return new Promise((resolve, reject) => {
            try {
                this.db.get(key, options, (err, value) => {
                    if(err) {
                        // Rather than erroring, just return nothing.
                        resolve()
                    }
                    else {
                        resolve(value);
                    }
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }

    async getMany(keys, options) {
        return new Promise((resolve, reject) => {
            try {
                this.db.getMany(keys, options, (err, values) => {
                    if(err) {
                        // err will have a value if the key does not exist, but in that case we would rather return nothing than error.
                        resolve()
                    }
                    else {
                        resolve(values);
                    }
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }
    
    async close() {
        return new Promise((resolve, reject) => {
            try {
                this.db.close((err) => {
                    if(err) {
                        reject(err);
                    }
                    else {
                        resolve();
                    }
                });
            }
            catch(err) {
                reject(err);
            }
        });
    }
}

module.exports = RocksDB;