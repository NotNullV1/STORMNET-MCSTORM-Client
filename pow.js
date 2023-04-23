const { parentPort, workerData } = require('node:worker_threads');
const crypto = require('crypto');

function sha256(input) {
  const hash = crypto.createHash('sha256');
  hash.update(input);
  return hash.digest('hex');
}

function pow(string, difficulty) {
  var lead = '';
  for (var i = 0; i < difficulty; i++) {
  	lead += "0";
  }
  var hash = '';
  var count = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
  while (!hash.startsWith(lead)) {
    count++;
    const final = string+count;
    hash = sha256(final)
  }
  return count
}

parentPort.postMessage(pow(workerData.string, workerData.difficulty))

process.exit()