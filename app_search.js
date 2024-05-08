const { Worker } = require("worker_threads");

const bitcoin_util = require("./util/bitcoin_util.js");
const log_util = require("./util/log_util.js");

const NUM_BATCHES_PER_WORKER = 10000;
const BATCH_SIZE = 32;
const NUM_WORKERS = 4;
const NUM_BITS = 4;
const TIMER_INTERVAL = 1000;

const WORKER_FILE = "./worker_task.js";

// Replace with the path to the folder where you have created the database
let dbPath = "C:\\GITHUB\\crypto\\DB";

let keysProcessed = 0;

processAllKeys();

async function processAllKeys() {
    init();

    let x = new Date();
    console.log("START: " + x);

    const interval = setInterval(() => {
        console.log("KEYS: " + keysProcessed + " NOW: " + new Date());
    }, TIMER_INTERVAL);

    await processKeys();

    clearInterval(interval);

    let y = new Date();
    console.log("END: " + y);

    finish();

    let seconds = Math.abs(y - x) / 1000;

    console.log("###################");
    console.log("Seconds: " + seconds);
    console.log("Keys: " + keysProcessed);
    console.log("Seconds/Key: " + seconds / keysProcessed);
    console.log("Keys/Second: " + keysProcessed / seconds);
    console.log("###################");
}

async function processKeys() {
    let promiseArray = [];
    for(let i = 0; i < NUM_WORKERS; i++) {
        promiseArray.push(workerFunc());
    }

    await Promise.all(promiseArray);
}

async function workerFunc() {
    return new Promise(async (resolve, reject) => {
        const worker = new Worker(WORKER_FILE, {
            workerData: {
                dbPath: dbPath,
                numBatches: NUM_BATCHES_PER_WORKER,
                batchSize: BATCH_SIZE
            }
        });
        worker.on("message", () => {
            keysProcessed += BATCH_SIZE;
        })
        worker.on("exit", () => {
            resolve();
        });
        worker.on("error", (err) => {
            log_util.logError(err);
            resolve();
        });
    });
}

function init() {
    console.log("Init Start: " + new Date());
    bitcoin_util.init(NUM_BITS);
    console.log("Init End: " + new Date());
}

function finish() {
    console.log("Finish Start: " + new Date());
    bitcoin_util.finish();
    console.log("Finish End: " + new Date());
}