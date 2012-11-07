/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

let DEBUG = 0;
function debug()
{
  if (DEBUG) {
    let output = [];
    for (let prop in arguments) {
      output.push(arguments[prop]);
    }
    dump("-*- webapps.jsm: " + output.join(" ") + "\n");
  }
}

const Cu = Components.utils;
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

let EXPORTED_SYMBOLS = [
                         "NulltxtReader",
                       ];

// We use NSS for the crypto ops, which needs to be initialized before
// use. By convention, PSM is required to be the module that
// initializes NSS. So, make sure PSM is initialized in order to
// implicitly initialize NSS.
Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "ppmm",
                                   "@mozilla.org/parentprocessmessagemanager;1",
                                   "nsIMessageBroadcaster");

XPCOMUtils.defineLazyServiceGetter(this, "cpmm",
                                   "@mozilla.org/childprocessmessagemanager;1",
                                   "nsIMessageSender");

XPCOMUtils.defineLazyGetter(this, "msgmgr", function() {
  return Cc["@mozilla.org/system-message-internal;1"]
         .getService(Ci.nsISystemMessagesInternal);
});

XPCOMUtils.defineLazyServiceGetter(this, "secretDecoderRing",
                                   "@mozilla.org/security/sdr;1",
                                   "nsISecretDecoderRing");

XPCOMUtils.defineLazyServiceGetter(this, "uuidSvc", function() {
  return Cc["@mozilla.org/uuid-generator;1"].getService(Ci.nsIUUIDGenerator);
});

// A new blank configuration object
var BLANK_CONFIG_OBJECT = {
  default: {
    created: null,
    privKey: null,
    pubKey: null,
    salt: null,
    iv: null
  }
};

// A blank configuration object as a string
var BLANK_CONFIG_OBJECT_STR = "{default: {created: null,privKey: null,pubKey: null,salt: null,iv: null}};";

function makeNewConfigObject()
{
  BLANK_CONFIG_OBJECT.default.passphrase =
    secretDecoderRing.encryptString(uuidSvc.generateUUID().toString());
  return JSON.stringify(BLANK_CONFIG_OBJECT);
}

// We can call ChromeWorkers from this JSM
XPCOMUtils.defineLazyGetter(this, "worker", function (){
  return new ChromeWorker("nulltxt_worker.js");
});

const PASSPHRASE = "32d0f984-841d-4e5e-b8ad-26f4928998c0"; // XXX: change this to a random value that is stored encrypted on disk

const CONFIG_FILE_PATH = ".nulltxt.json";
const PROFILE_DIR      = "ProfD";
// const STRINGS_URI      = "chrome://nulltxt/locale/nulltxt.properties";

const KEYPAIR_GENERATED   = "keypairGenerated";
const DATA_ENCRYPTED      = "dataEncrypted";
const DATA_DECRYPTED      = "dataDecrypted";
const MESSAGE_SIGNED      = "messageSigned";
const MESSAGE_VERIFIED    = "messageVerified";
const SHA256_COMPLETE     = "SHA256Complete";
const WORKER_ERROR        = "error";

worker.onmessage = function DCM_worker_onmessage(aEvent) {
  switch (aEvent.data.action) {
  case KEYPAIR_GENERATED:
    Callbacks.handleGenerateKeypair(aEvent.data.keypairData);
    break;
  case DATA_ENCRYPTED:
    Callbacks.handleEncrypt(aEvent.data.cipherMessage);
    break;
  case DATA_DECRYPTED:
    Callbacks.handleDecrypt(aEvent.data.plainText);
    break;
  case MESSAGE_SIGNED:
    Callbacks.handleSign(aEvent.data.signature);
    break;
  case MESSAGE_VERIFIED:
    Callbacks.handleVerify(aEvent.data.verification);
    break;
  case SHA256_COMPLETE:
    Callbacks.handleSHA256(aEvent.data.hashedString);
    break;
  case WORKER_ERROR:
    if (aEvent.data.notify) {
      notifyUser(aEvent.data);
    }
  default:
    break;
  }
};

worker.onerror = function DCM_onerror(aError) {
  log("Worker Error: " + aError.message);
  log("Worker Error filename: " + aError.filename);
  log("Worker Error line no: " + aError.lineno);
};


var DOMCryptMethods = {

  xullWindow: null,

  setXULWindow: function DCM_setXULWindow(aWindow)
  {
    this.xulWindow = aWindow;
  },

  /**
   * The config object that is created by reading the contents of
   * <profile>/.mozCipher.json
   */
  config: BLANK_CONFIG_OBJECT,

  /**
   * Initialize the DOMCryptMethods object: set the callback and
   * configuration objects
   *
   * @param Object aConfigObject
   * @param String aSharedObjectPath
   *        The path to the NSS shared object
   * @returns void
   */
  init: function DCM_init(aConfigObject, aSharedObjectPath)
  {
    this.config = aConfigObject;
    worker.postMessage({action: INITIALIZE_WORKER, nssPath: aSharedObjectPath});
  },

  /**
   * Remove all references to windows on window close or browser shutdown
   *
   * @returns void
   */
  shutdown: function DCM_shutdown()
  {
    worker.postMessage({ action: "shutdown" });

    this.sandbox = null;
    this.xulWindow = null;

    for (let prop in Callbacks) {
      Callbacks[prop].callback = null;
      Callbacks[prop].sandbox = null;
    }
    Callbacks = null;
  },

  callbacks: null,

  /////////////////////////////////////////////////////////////////////////
  // DOMCrypt API methods exposed via the nsIDOMGlobalPropertyInitializer
  /////////////////////////////////////////////////////////////////////////

  /**
   * Begin the generate keypair process
   *
   * 1. Prompt user for passphrase and confirm passphrase
   * 2. Pass the passphrase off to the worker to generate a keypair
   *
   * @returns void
   */
  beginGenerateKeypair: function DCM_beginGenerateKeypair(aCallback, aSandbox)
  {
    // TODO: check if the user already has a keypair and confirm they
    // would like to overwrite it

    Callbacks.register(GENERATE_KEYPAIR, aCallback, aSandbox);

    // TODO: remove any kind of passphrase here.
    // We will protect the private key on disk with the SDR
    this.generateKeypair(PASSPHRASE);


    // let passphrase = {};
    // let prompt =
    //   promptSvc.promptPassword(Callbacks.generateKeypair.sandbox.window,
    //                            getStr("enterPassphraseTitle"),
    //                            getStr("enterPassphraseText"),
    //                            passphrase, null, { value: false });
    // if (prompt && passphrase.value) {
    //   let passphraseConfirm = {};
    //   let prompt =
    //     promptSvc.promptPassword(Callbacks.generateKeypair.sandbox.window,
    //                              getStr("confirmPassphraseTitle"),
    //                              getStr("confirmPassphraseText"),
    //                              passphraseConfirm,
    //                              null, { value: false });
    //   if (prompt && passphraseConfirm.value &&
    //       (passphraseConfirm.value == passphrase.value)) {
    //     this.generateKeypair(passphrase.value);
    //   }
    //   else {
    //     promptSvc.alert(Callbacks.generateKeypair.sandbox.window,
    //                     getStr("passphrasesDoNotMatchTitle"),
    //                     getStr("passphrasesDoNotMatchText"));
    //   }
    // }
  },

  /**
   * The internal 'generateKeypair' method that calls the worker
   *
   * @param string aPassphrase
   * @returns void
   */
  generateKeypair: function DCM_generateKeypair()
  {
    worker.postMessage({ action: GENERATE_KEYPAIR, passphrase: PASSPHRASE });
    // this.passphraseCache.encryptedPassphrase = secretDecoderRing.encryptString(aPassphrase);
    // this.passphraseCache.lastEntered = Date.now();

  },

  /**
   * The internal 'getPublicKey' method
   *
   * @returns void
   */
  ////////////////////////////////////////////////////////////////////////////////
  // XXX: not using this method anymore.
  // Applicaiton developer needs to store the pub key on first generation
  //
  // getPublicKey: function DCM_getPublicKey(aCallback, aSandbox)
  // {
  //   Callbacks.register(GET_PUBLIC_KEY, aCallback, aSandbox);
  //   // TODO: need a gatekeeper function/prompt to allow access to your publicKey
  //   // TODO: looks like we can get this async via FileUtils
  //   Callbacks.handleGetPublicKey(this.config.default.pubKey);
  // },

  /**
   * The internal 'encrypt' method which calls the worker to do the encrypting
   *
   * @param string aPlainText
   * @param string aPublicKey
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  encrypt: function DCM_encrypt(aPlainText, aPublicKey, aCallback, aSandbox)
  {
    Callbacks.register(ENCRYPT, aCallback, aSandbox);

    worker.postMessage({ action: ENCRYPT,
                         pubKey: aPublicKey,
                         plainText: aPlainText
                       });
  },

  /**
   * The internal 'decrypt' method which calls the worker to do the decrypting
   *
   * @param Object aCipherMessage
   * @param string aPassphrase
   * @returns void
   */
  decrypt:
  function DCM_decrypt(aCipherMessage)
  {

    let userIV = secretDecoderRing.decryptString(this.config.default.iv);
    let userSalt = secretDecoderRing.decryptString(this.config.default.salt);
    let userPrivKey = this.config.default.privKey;
    let cipherMessage = XPCNativeWrapper.unwrap(aCipherMessage);

    worker.postMessage({ action: DECRYPT,
                         // cipherMessage: aCipherMessage,
                         cipherContent: cipherMessage.content,
                         cipherWrappedKey: cipherMessage.wrappedKey,
                         cipherPubKey: cipherMessage.pubKey,
                         cipherIV: cipherMessage.iv,
                         passphrase: PASSPHRASE,
                         privKey: userPrivKey,
                         salt: userSalt,
                         iv: userIV
                       });
  },

  passphraseCache: {
    encryptedPassphrase: null,
    lastEntered: null,
  },

  /**
   * Get the passphrase
   *
   * @returns string
   */
  get passphrase() {
    let passphrase = this.checkPassphraseCache();
    return passphrase;
  },

  /**
   * Check to see if the cached (encrypted) passphrase needs to be re-entered
   *
   * @returns void
   */
  checkPassphraseCache: function DCM_checkPassphraseCache()
  {
    // let passphrase;
    // // check if the passphrase has ever been entered
    // if (!this.passphraseCache.encryptedPassphrase) {
    //   passphrase = this.enterPassphrase();
    // }
    // // check if the passphrase is outdated and needs to be re-entered
    // else if ((Date.now() - this.passphraseCache.lastEntered) > PASSPHRASE_TTL) {
    //   passphrase = this.enterPassphrase();
    // }
    // else {
    //   return secretDecoderRing.decryptString(this.passphraseCache.encryptedPassphrase);
    // }
    return PASSPHRASE;
  },

  // /**
  //  * Prompt the user for a passphrase to begin the decryption process
  //  *
  //  * @param object aCipherMessage
  //  * @param function aCallback
  //  * @param sandbox aSandbox
  //  * @returns void
  //  */
  // promptDecrypt: function DCM_promptDecrypt(aCipherMessage, aCallback, aSandbox)
  // {
  //   Callbacks.register(DECRYPT, aCallback, aSandbox);
  //   let passphrase = this.passphrase;

  //   if (passphrase) {
  //     this.decrypt(aCipherMessage, passphrase);
  //     return;
  //   }

  //   throw new Error(getStr("noPassphraseEntered"));
  // },

  /**
   * Front-end 'sign' method prompts user for passphrase then
   * calls the internal _sign message
   *
   * @param string aPlainTextMessage
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  sign: function DCM_sign(aPlainTextMessage, aCallback, aSandbox)
  {
    // Callbacks.register(SIGN, aCallback, aSandbox);
    // let passphrase = this.passphrase;
    // if (passphrase) {
    this._sign(aPlainTextMessage);
    // }
    // else {
    //   throw new Error(getStr("noPassphraseEntered"));
    // }
  },

  /**
   * Internal backend '_sign' method calls the worker to do the actual signing
   *
   * @param string aPlainTextMessage
   * @param string aPassphrase
   * @returns void
   */
  _sign: function DCM__sign(aPlainTextMessage)
  {
    let userIV = secretDecoderRing.decryptString(this.config.default.iv);
    let userSalt = secretDecoderRing.decryptString(this.config.default.salt);
    // XXX: use key ID
    let userPrivKey = this.config.default.privKey;
    let hash = this._SHA256(aPlainTextMessage);

    worker.postMessage({ action: SIGN,
                         hash: hash,
                         passphrase: PASSPHRASE,
                         iv: userIV,
                         salt: userSalt,
                         privKey: userPrivKey
                       });
  },

  /**
   * The 'verify' method which calls the worker to do signature verification
   *
   * @param string aPlainTextMessage
   * @param string aSignature
   * @param string aPublicKey
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  verify:
  function
  DCM_verify(aPlainTextMessage, aSignature, aPublicKey, aCallback, aSandbox)
  {
    // Callbacks.register(VERIFY, aCallback, aSandbox);
    let hash = this._SHA256(aPlainTextMessage);

    // Create a hash in the worker for verification
    worker.postMessage({ action: VERIFY,
                         hash: hash,
                         signature: aSignature,
                         pubKey: aPublicKey
                       });
  },

  /**
   * This is the internal SHA256 hash function, it does the actual hashing
   *
   * @param string aPlainText
   * @returns string
   */
  _SHA256: function DCM__SHA256(aPlainText)
  {
    // stolen from weave/util.js
    let converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].
                      createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";

    let hasher = Cc["@mozilla.org/security/hash;1"].
                   createInstance(Ci.nsICryptoHash);
    hasher.init(hasher.SHA256);

    let data = converter.convertToByteArray(aPlainText, {});
    hasher.update(data, data.length);
    let rawHash = hasher.finish(false);

    // return the two-digit hexadecimal code for a byte
    function toHexString(charCode) {
      return ("0" + charCode.toString(16)).slice(-2);
    }

    let hash = [toHexString(rawHash.charCodeAt(i)) for (i in rawHash)].join("");
    return hash;
  },

  /**
   * SHA256 API hash function
   * This is synchronous for the time being. TODO: wrap NSS SHA* functions
   * with js-ctypes so we can run in a worker
   *
   * @param string aPlainTextMessage
   * @returns void
   */
  SHA256: function DCM_SHA256(aPlainText, aCallback, aSandbox)
  {
    Callbacks.register(SHA256, aCallback, aSandbox);
    let hash = this._SHA256(aPlainText);
    // let callback = Callbacks.makeSHA256Callback(hash);
    // let sandbox = Callbacks.SHA256.sandbox;
    // sandbox.importFunction(callback, "SHA256Callback");
    // Cu.evalInSandbox("SHA256Callback();", sandbox, "1.8", "DOMCrypt", 1);
  },

  getAddressbook: function DCM_getAddressbook(aAddressbook, aCallback, aSandbox)
  {
    // XXX: we are faking async here
    // Callbacks.register(GET_ADDRESSBOOK, aCallback, aSandbox);
    // let callback = Callbacks.makeGetAddressbookCallback(aAddressbook);
    // let sandbox = Callbacks.getAddressbook.sandbox;
    // sandbox.importFunction(callback, "getAddressbookCallback");
    // Cu.evalInSandbox("getAddressbookCallback();", sandbox, "1.8", "DOMCrypt", 1);
  },


  /**
   * Get the configuration file from the filesystem.
   * The file is a JSON file in the user's profile named ".mozCipher.json"
   * @param boolean aFileCreated
   * @returns nsIFile
   */
  configurationFile: function DCM_configFile(aFileCreated)
  {
    // get profile directory
    let file = FileUtils.getFile(PROFILE_DIR, [CONFIG_FILE_PATH], true);
    if (!file.exists()) {
      file.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0600);
      aFileCreated.value = true;
    }
    else {
      aFileCreated.value = false;
    }
    return file;
  },

  /**
   * write an updated or new configuration to <profile>/.mozCipher.json
   *
   * @param Object aConfigObj
   * @returns void
   */
  writeConfigurationToDisk: function DCM_writeConfigurationToDisk(aConfigObj)
  {
    if (!aConfigObj) {
      throw new Error("aConfigObj is null");
    }

    let data;

    if (typeof aConfigObj == "object") {
      // convert aConfigObj to JSON string
      data = JSON.stringify(aConfigObj);
    }
    else {
      data = aConfigObj;
    }
    let foStream = Cc["@mozilla.org/network/file-output-stream;1"].
      createInstance(Ci.nsIFileOutputStream);
    let fileCreated = {};
    let file = this.configurationFile(fileCreated);

    // use 0x02 | 0x10 to open file for appending.
    foStream.init(file, 0x02 | 0x08 | 0x20, 0666, 0);
    let converter = Cc["@mozilla.org/intl/converter-output-stream;1"].
      createInstance(Ci.nsIConverterOutputStream);
    converter.init(foStream, "UTF-8", 0, 0);
    converter.writeString(data);
    converter.close();
  },

  config: BLANK_CONFIG_OBJECT,
};

let NulltxtReader = {
  init: function ntr_init()
  {
    this.messages = [
                     "NulltxtReader:Read",
                     "NulltxtReader:Write",
                     "NulltxtReader:OpenUI",
                     "NulltxtReader:CloseUI",
                    ];

    this.messages.forEach((function(msgName) {
      ppmm.addMessageListener(msgName, this);
    }).bind(this));

    cpmm.addMessageListener("Activities:Register:OK", this);

    Services.obs.addObserver(this, "xpcom-shutdown", false);
  },

  observe: function ntr_observe(aSubject, aTopic, aData) {
    if (aTopic == "xpcom-shutdown") {
      this.messages.forEach((function(msgName) {
        ppmm.removeMessageListener(msgName, this);
      }).bind(this));
      Services.obs.removeObserver(this, "xpcom-shutdown");
      ppmm = null;
    }
  },

  openUI: function ntr_openUI(aMsg)
  {

  },

  closeUI: function ntr_closeUI(aMsg)
  {

  },

  read: function ntr_read(aMsg)
  {

  },

  write: function ntr_write(aMsg)
  {

  },

  receiveMessage: function(aMessage) {
    let msg = aMessage.json;
    let mm = aMessage.target;
    msg.mm = mm;

    switch (aMessage.name) {
      case "NulltxtReader:Read":

        break;
      case "NulltxtReader:Write":

        break;
      case "NulltxtReader:OpenUI":
        this.openUI(msg);
        break;
      case "NulltxtReader:CloseUI":
      this.closeUI(msg);
        break;
    default:
      return;
    }
  },
};

NulltxtReader.init();

let CryptoAPI = {

  getKeypair: function CA_getKeypair(aKeyID)
  {
    if (aKeyID) {
      // look up the keypair on disk
    }
    else {

    }
  },

  hide: function CA_hide(aClearMsg, aPublicKey)
  {
    // actual arguments for an "encryptAndSign" function:
    // eAndS(aClearMsg, aPubKey, aPassphrase, aPrivKey, aIV, aSalt);
    // we do: cipherMessage = encrypt(aPlainText, aPublicKey) first
    // we hash the message content:
    // hash = sha256Hash(cipherMessage.content);
    // we sign the message:
    // sig = sign(hash, aPassphrase, aPrivateKey, aIV, aSalt);
    // add the signature to the cipherMessage:
    // cipherMessage.signature = sig;
    // we return the hidden object:
    // return cipherMessage;
  },

  show: function CA_show(aCipherMsg, aKeyID)
  {
    // procedure:
    // verfiy the signature in the cipherMsg
    // throw if the signature does not verify cleanly

    // decrypt the cipherMsg

  },

  sign: function CA_sign(aData, aKeyID)
  {

  },

  verify: function CA_verify(aData, aSignature, aPubKey)
  {

  },

  hash: function CA_hash(aData)
  {

  },

  version: "1",

};

/**
 * Initialize the DOMCryptMethods object by getting the configuration object
 * and creating the callbacks object
 * @param outparam aDOMCrypt
 * @returns void
 */
function initializeDOMCrypt()
{
  // Full path to NSS via js-ctypes
  let path = Services.dirsvc.get("GreD", Ci.nsILocalFile);
  let libName = ctypes.libraryName("nss3"); // platform specific library name
  path.append(libName);
  let fullPath = path.path;

  let fileCreated = {};
  let file = DOMCryptMethods.configurationFile(fileCreated);

  NetUtil.asyncFetch(file, function(inputStream, status) {
    if (!Components.isSuccessCode(status)) {
      throw new Error("Cannot access DOMCrypt configuration file");
    }

    var data;
    if (fileCreated.value) {
      // data = JSON.stringify(BLANK_CONFIG_OBJECT);
      data = makeNewConfigObject();
      writeConfigObjectToDisk(data, function writeCallback (status) {
        if (!Components.isSuccessCode(status)) {
          throw new Error("Cannot write config object file to disk");
        }
        let configObj = JSON.parse(data);
        DOMCryptMethods.init(configObj, fullPath);
      });
    }
    else {
      data = NetUtil.readInputStreamToString(inputStream, inputStream.available());
      let configObj = JSON.parse(data);
      DOMCryptMethods.init(configObj, fullPath);
    }
  });
}

/**
 * Write the configuration to disk
 *
 * @param string aData
 * @param function aCallback
 * @returns void
 */
function writeConfigObjectToDisk(aData, aCallback)
{
  let fileCreated = {};
  let file = DOMCryptMethods.configurationFile(fileCreated);

  let ostream = Cc["@mozilla.org/network/file-output-stream;1"].
                  createInstance(Ci.nsIFileOutputStream);

  let converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].
                    createInstance(Ci.nsIScriptableUnicodeConverter);
  converter.charset = "UTF-8";
  let istream = converter.convertToInputStream(aData);

  NetUtil.asyncCopy(istream, ostream, aCallback);
}

initializeDOMCrypt();
