const {parentPort, workerData} = require("worker_threads");

const RocksDB = require("./RocksDB.js");

const bitcoin_util = require("./util/bitcoin_util.js");
const log_util = require("./util/log_util.js");

foo();

async function foo() {
    const rocksdb = new RocksDB(workerData.dbPath);
    await rocksdb.open({readOnly: true, maxOpenFiles: 2000});

    const batchSize = workerData.batchSize;

    for(let i = 0; i < workerData.numBatches; i++) {
        const privateKeyArray = createPrivateKey(batchSize);
        const addressArray = bitcoin_util.getAddressArray(privateKeyArray, batchSize);

        let values = await rocksdb.getMany(addressArray);
        if(values.some(element => element)) {
            // In the rare event we find something, spend the time testing each private key individually.
            for(let j = 0; j < batchSize; j++) {
                const offset = 32 * j;
                const privateKey = privateKeyArray.slice(offset, offset + 32);
                const addressArray2 = bitcoin_util.getAddressArray(privateKey, 1);
                const types = bitcoin_util.getTypeArray();
                let values2 = await rocksdb.getMany(addressArray2);
                if(values2.some(element => element)) {
                    // Write the private key along with any public keys that are in the database.
                    const privateKeyHex = Buffer.from(privateKey).toString("hex");
                    let infoString = "Private Key: " + privateKeyHex;
                    for(let k = 0; k < addressArray2.length; k++) {
                        if(values2[k]) {
                            infoString += "\n    " + types[k] + ": " + addressArray2[k];
                        }
                    }
                    console.log(infoString);
                    log_util.log(infoString);
                }
            }
        }

        parentPort.postMessage(null);
    }

    await rocksdb.close();
}

function createPrivateKey(batchSize) {
    // Create random array of 32 * batchSize numbers 0-255.
    return Uint8Array.from(Array.from({length: 32 * batchSize}, () => Math.floor(Math.random() * 256)));
}