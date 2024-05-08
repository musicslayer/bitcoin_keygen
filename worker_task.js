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
        //if(values.some(element => element)) {
        if(true) {
            // In the rare event we find something, spend the time testing each private key individually.
            for(let j = 0; j < batchSize; j++) {
                const offset = 32 * j;
                const privateKey = privateKeyArray.slice(offset, offset + 32);
                const addressArray2 = bitcoin_util.getAddressArray(privateKey, 1);
                let values2 = await rocksdb.getMany(addressArray2);
                //if(values2.some(element => element)) {
                if(true) {
                    const privateKeyHex = Buffer.from(privateKey).toString("hex");
                    const infoString = privateKeyHex;
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

// Use for puzzles
/*
function createPrivateKey(batchSize) {
    const NUM_N = 9;
    const NUM_Z = 32 - NUM_N;

    let arr = [];

    for(let i = 0; i < batchSize; i++) {
        arr.push(Array(NUM_Z).fill(0));
        arr.push(Array.from({length: NUM_N}, () => Math.floor(Math.random() * 256)));
    }

    return Uint8Array.from(arr.flat());
}
*/