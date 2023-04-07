const fs = require("fs");

const LOG_FOLDER = "logs"
const LOG_FILE = "logs/log.txt"
const LOG_ERROR_FILE = "logs/log_error.txt"

initializeLogs();

function initializeLogs() {
    if(!fs.existsSync(LOG_FOLDER)) {
        fs.mkdirSync(LOG_FOLDER);
    }
    if(!fs.existsSync(LOG_FILE)) {
        fs.writeFileSync(LOG_FILE, "");
    }
    if(!fs.existsSync(LOG_ERROR_FILE)) {
        fs.writeFileSync(LOG_ERROR_FILE, "");
    }
}

function log(infoString) {
    fs.appendFileSync(LOG_FILE, infoString + "\n");
}

function logError(error) {
    const errorString = "ERROR: " + error + "\n" +
        "ERROR STACK: " + error.stack + "\n\n";

    fs.appendFileSync(LOG_ERROR_FILE, errorString);
}

module.exports.log = log;
module.exports.logError = logError;