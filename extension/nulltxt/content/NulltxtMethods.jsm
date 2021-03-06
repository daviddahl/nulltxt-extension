/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *  Author: David Dahl <ddahl@mozilla.com>
 *
 * */

let Cu = Components.utils;
let Ci = Components.interfaces;
let Cc = Components.classes;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "promptSvc",
                                   "@mozilla.org/embedcomp/prompt-service;1",
                                   "nsIPromptService");

XPCOMUtils.defineLazyServiceGetter(this, "secretDecoderRing",
                                   "@mozilla.org/security/sdr;1",
                                   "nsISecretDecoderRing");

XPCOMUtils.defineLazyServiceGetter(this, "ppmm",
                                   "@mozilla.org/parentprocessmessagemanager;1",
                                   "nsIMessageBroadcaster");

XPCOMUtils.defineLazyServiceGetter(this, "cpmm",
                                   "@mozilla.org/childprocessmessagemanager;1",
                                   "nsIMessageSender");

XPCOMUtils.defineLazyServiceGetter(this, "uuidSvc",
                                   "@mozilla.org/uuid-generator;1",
                                   "nsIUUIDGenerator");

XPCOMUtils.defineLazyGetter(this, "msgmgr", function() {
  return Cc["@mozilla.org/system-message-internal;1"]
         .getService(Ci.nsISystemMessagesInternal);
});

log("\n\nINITIAL LOAD OF NULLTXTMETHODS\n\n");

var PASSPHRASE_TTL = 3600000;
const PASSPHRASE = "32d0f984-841d-4e5e-b8ad-26f4928998c0";

const CONFIG_FILE_PATH = ".nulltxt.json";
const PROFILE_DIR      = "ProfD";
const STRINGS_URI      = "chrome://nulltxt/locale/nulltxt.properties";

XPCOMUtils.defineLazyGetter(this, "stringBundle", function () {
  return Services.strings.createBundle(STRINGS_URI);
});

/**
 * This string object keeps track of all of the string names used here
 */
const MOZ_CIPHER_STRINGS = {
  enterPassphraseTitle: "enterPassphraseTitle",
  enterPassphraseText: "enterPassphraseText",
  confirmPassphraseTitle: "confirmPassphraseTitle",
  confirmPassphraseText: "confirmPassphraseText",
  enterPassphraseInitTitle: "enterPassphraseInitTitle",
  enterPassphraseInitText: "enterPassphraseInitText",
  confirmPassphraseInitTitle: "confirmPassphraseInitTitle",
  confirmPassphraseInitText: "confirmPassphraseInitText",
  passphrasesDoNotMatchTitle: "passphrasesDoNotMatchTitle",
  passphrasesDoNotMatchText: "passphrasesDoNotMatchText",
  signErrorTitle: "signErrorTitle",
  signErrorMessage: "signErrorMessage",
  noPassphraseEntered: "noPassphraseEntered",
};

/**
 * Memoize and return all strings used by this JSM
 */
function _stringStorage(aName) { }

_stringStorage.prototype = {

  /**
   * Internally memoizes and gets the string via aName
   *
   * @param string aName
   * @returns string
   */
  getStr: function SS_getStr(aName) {
    if (MOZ_CIPHER_STRINGS[aName]) {
      if (this[aName]) {
        return this[aName];
      }
      else {
        this[aName] = stringBundle.GetStringFromName(aName);
        return this[aName];
      }
    }
    else {
      Cu.reportError("Cannot get " + aName + " from stringBundle");
      return "";
    }
  },
};

// Initialize the stringStorage object
var stringStorage = new _stringStorage();

/**
 * StringBundle shortcut function
 *
 * @param string aName
 * @returns string
 */
function getStr(aName)
{
  return stringStorage.getStr(aName);
}

const DEBUG = false;

function log(aMessage) {
  if (!DEBUG) {
    return;
  }
  var _msg = "*** NulltxtMethods: " + aMessage + "\n";
  dump(_msg);
}

function pprint(aObj)
{
  if (!DEBUG) {
    return;
  }
  if (typeof aObj == "object") {
    for (let prop in aObj) {
      if (typeof aObj[prop] == "function") {
        log("function " + prop);
      }
      else {
        log(prop + ": " + aObj[prop]);
      }
    }
  }
  else {
    log(aObj);
  }
}

var EXPORTED_SYMBOLS = ["NulltxtMethods"];

// A new blank configuration object
var BLANK_CONFIG_OBJECT = {
  default: {
    created: "",
    privKey: "",
    pubKey: "",
    salt: "",
    iv: ""
  },
  idIndex: { }
};

// A blank configuration object as a string
var BLANK_CONFIG_OBJECT_STR = JSON.stringify(BLANK_CONFIG_OBJECT);
//"{default: {created: null,privKey: null,pubKey: null,salt: null,iv: null}};";

// We use NSS for the crypto ops, which needs to be initialized before
// use. By convention, PSM is required to be the module that
// initializes NSS. So, make sure PSM is initialized in order to
// implicitly initialize NSS.
Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);

// We can call ChromeWorkers from this JSM
XPCOMUtils.defineLazyGetter(this, "worker", function (){
  return new ChromeWorker("nulltxt_worker.js");
});

const KEYPAIR_GENERATED   = "keypairGenerated";
const DATA_ENCRYPTED      = "dataEncrypted";
const DATA_HIDDEN         = "dataHidden";
const DATA_DECRYPTED      = "dataDecrypted";
const DATA_SHOWN          = "dataShown";
const MESSAGE_SIGNED      = "messageSigned";
const MESSAGE_VERIFIED    = "messageVerified";
const SYM_KEY_GENERATED   = "symKeyGenerated";
const SYM_ENCRYPTED       = "symEncrypted";
const SYM_DECRYPTED       = "symDecrypted";
const SYM_KEY_WRAPPED     = "symKeyWrapped";
const SHA256_COMPLETE     = "SHA256Complete";
const PASSPHRASE_VERIFIED = "passphraseVerified";
const WORKER_ERROR        = "error";

worker.onmessage = function DCM_worker_onmessage(aEvent) {
  log("worker.onmessage");
  log(aEvent.data.action);
  switch (aEvent.data.action) {
  case KEYPAIR_GENERATED:
    // Callbacks.handleGenerateKeypair(aEvent.data.keypairData);
    // cpmm.sendAsyncMessage("Bridge:Keypair:Generated", aEvent.data.keypairData);
    NulltxtMethods.completeInitialization(aEvent.data.keypairData);
    break;
  case DATA_ENCRYPTED:
    log("worker.onmessage -> DATA_ENCRYPTED");
    // Callbacks.handleEncrypt(aEvent.data.cipherMessage);
    // We need to get the request ID,
    // message the child process with the resultant cipherMessage
    // have the child process call the fireSuccess on the DOMRequest,
    // passing the new encrypted cipherObject back to the content DOM
    NulltxtMethods.returnCipherObject(aEvent.data);
    break;
  case DATA_HIDDEN:
    log("\n\n Data Shown \n\n");
    pprint(aEvent.data);
    NulltxtMethods.returnCipherObject(aEvent.data);
    break;
  case DATA_SHOWN:
    log("\n\n Data Shown \n\n");
    pprint(aEvent.data);
    NulltxtMethods.returnCipherObject(aEvent.data);
    break;
  case DATA_DECRYPTED:
    // Callbacks.handleDecrypt(aEvent.data.plainText);
    DOMCryptMethods.UIWidgets[aEvent.data._windowID].
      displayDecryptedText(aEvent.data.plainText);
    break;
  case MESSAGE_SIGNED:
    // Callbacks.handleSign(aEvent.data.signature);
    break;
  case MESSAGE_VERIFIED:
    // Callbacks.handleVerify(aEvent.data.verification);
    break;
  case SYM_KEY_GENERATED:
    // Callbacks.handleGenerateSymKey(aEvent.data.wrappedKeyObject);
    break;
  case SYM_ENCRYPTED:
    // Callbacks.handleSymEncrypt(aEvent.data.cipherObject);
    break;
  case SYM_DECRYPTED:
    // Callbacks.handleSymDecrypt(aEvent.data.plainText);
    break;
  case SYM_KEY_WRAPPED:
    // Callbacks.handleWrapSymKey(aEvent.data.cipherObject);
    break;
  case SHA256_COMPLETE:
    // Callbacks.handleSHA256(aEvent.data.hashedString);
    break;
  case PASSPHRASE_VERIFIED:
    // Callbacks.handleVerifyPassphrase(aEvent.data.verification);
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

// Constants to describe all operations
const GENERATE_KEYPAIR  = "generateKeypair";
const ENCRYPT           = "encrypt";
const DECRYPT           = "decrypt";
const SIGN              = "sign";
const VERIFY            = "verify";
const HIDE              = "hide";
const SHOW              = "show";
const VERIFY_PASSPHRASE = "verifyPassphrase";
const GENERATE_SYM_KEY  = "generateSymKey";
const SYM_ENCRYPT       = "symEncrypt";
const SYM_DECRYPT       = "symDecrypt";
const WRAP_SYM_KEY      = "wrapSymKey";
const GET_PUBLIC_KEY    = "getPublicKey";
const SHA256            = "SHA256";
const GET_ADDRESSBOOK   = "getAddressbook";
const INITIALIZE_WORKER = "init";

/**
 * DOMCryptMethods
 *
 * This Object handles all input from content scripts via the DOMCrypt
 * nsIDOMGlobalPropertyInitializer and sends calls to the Worker that
 * handles all NSS calls
 *
 * The basic work flow:
 *
 * A content script calls one of the DOMCrypt window API methods, at minimum,
 * a callback function is passed into the window API method.
 *
 * The window API method calls the corresponding method in this JSM
 * (DOMCryptMethods), which sets up the callback and sandbox.
 *
 * The DOMCryptMethod API calls into the ChromeWorker which initializes NSS and
 * provides the js-ctypes wrapper obejct which is a slightly edited and expanded
 * WeaveCrypto Object.
 *
 * The crypto operations are run in the worker, and the return value sent back to
 * the DOMCryptMethods object via a postMessage.
 *
 * DOMCryptMethods' onmessage chooses which callback to execute in the original
 * content window's sandbox.
 */
var DOMCryptMethods = {

  observe: function DCM_observe(aSubject, aTopic, aData)
  {
    log("observe aSubject: " + aSubject);
    log("observe aTopic: " + aTopic);
    log("observe aData: " + aData);
    switch (aTopic) {
    case "nulltxt-config-loaded":
      // Pubkey already generated, just open the UI
      if (!this.UIWidgets[aData]) {
        log("... creating CryptoConsole ...");
        this.UIWidgets[aData] = new CryptoConsole(aData);
        this.UIWidgets[aData].updateUI("pubKey", this.config);
      } // XXX: else... should change UI to keygen ui
        // Also, we should fireSuccess for content to get the pubkey
      break;
    case "nulltxt-keygen-complete":
      // XXX: need to tell the DOMRequest to fireSuccess(aPubKey, aKeyID)
      // get the pubkey data
      let pubkey = this.getPublicKeyByID(aSubject);
      this.messageManagers[aSubject].
        sendAsyncMessage("Bridge:UI:CipherObjectReturned",
                         { id: aSubject.data, // supportsString
                           publicKey: pubkey,
                           action: "keypairGenerated",
                           metaData: {
                             windowID: aData,
                             domReqID: aSubject.data, // supportsString
                           },
                         });
      break;
    case "nulltxt-initialization-complete":
      let win = this.getWindowByWindowId(aData);
      if (!win) {
        let err = "No window with ID: " + aData;
        log(err);
        Cu.reportError(err);
        return;
      }
      // notify user - open UI?
      if (!this.UIWidgets[aData]) {
        // XXX: need to actually check the DOM for the UI
        this.UIWidgets[aData] = new CryptoConsole(aData);
        this.UIWidgets[aData].updateUI("init", this.config);
      }
      else {
        log("aSubject" + aSubject);
        log("updateUI(keygen)");
        this.UIWidgets[aData].updateUI("keygen", this.config, aSubject);
      }
      break;
    default:
      break;
    }
  },

  receiveMessage: function DCM_receiveMessage(aMessage)
  {
    log("receiveMessage: " + aMessage);
    // pprint(aMessage);
    let msg = aMessage.data || {};
    let mm = aMessage.target;
    msg.mm = mm;

    switch (aMessage.name) {
      case "BridgeOps:GenerateKeypair":
        this.generateKeypair(PASSPHRASE);
        break;
      case "Bridge:UI:RegisterCipherObject":
        this.registerCipherObject(msg, mm);
        break;
      case "Bridge:UI:Initialize":
        log("Bridge:UI:Initialize");
        // pprint(msg);
        this.initializeSystem(msg, mm);
        break;
    default:
      break;
    }
  },

  initializeSystem: function DCM_initializeSystem(aMessage, aMsgManager)
  {
    log("initializeSystem()");
    let self = this;
    let fileCreated = {};
    // Make sure there is a configuration file
    let file = this.configurationFile(fileCreated);
    // If the file is not empty, attempt to get the public key data
    if (file.fileSize == 0 || fileCreated.value == true) {
      // empty file
      // If there is no publickey, generate one
      log("beginGenerateKeypair...");
      this.beginGenerateKeypair(aMessage.id);
      return;
    }
    else {
      log("... loadConfig() ...");
      // read config into memory
      loadConfig(file, function (aJSONObject) {
        if (aJSONObject) {
          self.config = aJSONObject;
          Services.obs.notifyObservers(null, "nulltxt-config-loaded", aMessage.id);
        }
      });
    }
  },

  doKeygen: function DCM_doKeygen(aMessage)
  {
    log("doKeygen()");
    this.beginGenerateKeypair(aMessage.id);
  },

  completeInitialization: function DCM_completeInitialization(aMessage)
  {
    log("complegteInitialization()");
    log("aMessage.id: " + aMessage.id);
    log("aMessage.requestID: " + aMessage.requestID);
    // what location are we generating this keypair for?
    let win = this.getWindowByWindowId(aMessage.id);
    log(win);
    let origin = win.location.host;
    log(origin);
    // check for existing config file:
    // XXX: let's assume a config file exists for now:)

    if (!this.config[origin]) {
      this.config[origin] = [];
    }

    // let uuid = uuidSvc.generateUUID();

    let pubKeyData = {
      id: aMessage.requestID,
      created: aMessage.created,
      privKey: aMessage.privKey,
      pubKey: aMessage.pubKey,
      salt: secretDecoderRing.encryptString(aMessage.salt),
      iv: secretDecoderRing.encryptString(aMessage.iv),
      host: win.location.host,
      protocol: win.location.protocol,
      port: win.location.port,
    };

    this.config[origin].push(
      pubKeyData
    );

    this.config.idIndex[aMessage.requestID] = pubKeyData;

    // // need to write the config data to disk
    // let config = JSON.parse(BLANK_CONFIG_OBJECT_STR);
    // config.default.created = aMessage.created;
    // config.default.privKey = aMessage.privKey;
    // config.default.pubKey = aMessage.pubKey;
    // config.default.salt = secretDecoderRing.encryptString(aMessage.salt);
    // config.default.iv = secretDecoderRing.encryptString(aMessage.iv);

    // config.default.host = win.location.host;
    // config.default.protocol = win.location.protocol;
    // config.default.port = win.location.port;

    // this.config = config;

    let fileCreated = {};
    let file = DOMCryptMethods.configurationFile(fileCreated);
    let data = JSON.stringify(this.config);
    writeConfig(file, data, function () {
      Services.obs.notifyObservers(supportsString(aMessage.requestID),
                                   "nulltxt-keygen-complete",
                                   aMessage.id);
    });
  },

  returnCipherObject: function DCM_returnCipherObject(aCipherObject)
  {
    // need to message child process wih this cipherObject...
    log("returnCipherObject()");
    pprint(aCipherObject);
    pprint(aCipherObject.metaData);
    let winID = aCipherObject.metaData.windowID;

    log("return Cipher Object");
    this.UIWidgets[winID]._mm.
      sendAsyncMessage("Bridge:UI:CipherObjectReturned", aCipherObject);

    if (!aCipherObject.plainText) {
      // reading plain text, display this text in the Chrome UI
      this.removeUI(winID);
      return;
    }
    // need to read this message in Chrome UI:
    this.UIWidgets[winID].readBox.statusText.
      setAttribute("value", aCipherObject.verification);
    this.UIWidgets[winID].readBox.statusLabel.
      setAttribute("value", "Signature Verified:");
    this.UIWidgets[winID].readBox.textBox.
      setAttribute("value", aCipherObject.plainText);
  },

  removeUI: function DCM_removeUI(aID)
  {
    this.UIWidgets[aID].destroyUI();
    delete this.UIWidgets[aID];
  },

  messageManagers: {

  },

  registerCipherObject: function DCM_registerCipherObject(aMessage, aMsgManager)
  {
    log("REGISTER CIPHER OBJECT");
    pprint(aMessage);

    // Are we generating a key?
    if (aMessage.type == "keygen") {
      this.messageManagers[aMessage._domReqID] = aMsgManager;
      this.beginGenerateKeypair(aMessage._windowID, aMessage._domReqID);
      return;
    }

    log(aMessage._windowID + ": " + this.UIWidgets[aMessage._windowID]);
    // see if we have a UI open for the window in question
    if (!this.UIWidgets[aMessage._windowID]) {
      try {
        this.UIWidgets[aMessage._windowID] =
          new CryptoConsole(aMessage._windowID, aMessage._domReqID);
      }
      catch (ex) {
        log(ex);
        log(ex.stack);
      }
    }

    log("\n\nUI Exists (now)....\n\n");
    // Handle each kind of potential message: read, write, sign, verify, hash
    // the aMessage._domReqID gets re-set inside handleMessage!
    this.UIWidgets[aMessage._windowID].handleMessage(aMessage);

    // attach the message manager to the UI widget for later use
    this.UIWidgets[aMessage._windowID]._mm = aMsgManager;
  },

  UIWidgets: {

  },

  xulWindow: null,

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
    log("NulltxtMethods init...");
    this.messages = ["Bridge:UI:RegisterCipherObject",
                     "Bridge:UI:Initialize",
                     "child-process-shutdown",
                    ];

    // this.frameMessages = ["Webapps:ClearBrowserData"];

    this.messages.forEach((function(msgName) {
      log("Adding message listener for: " + msgName);
      ppmm.addMessageListener(msgName, this);
    }).bind(this));

    Services.obs.addObserver(this, "nulltxt-initialization-complete", false);
    Services.obs.addObserver(this, "nulltxt-keygen-complete", false);
    Services.obs.addObserver(this, "nulltxt-config-loaded", false);

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
  },

  /////////////////////////////////////////////////////////////////////////
  // DOMCrypt API methods exposed via the nsIDOMGlobalPropertyInitializer
  /////////////////////////////////////////////////////////////////////////

  hide: function DCA_hide(aPlainText, aPublicKey, aKeyID, aMetaData)
  {
    log("hide()\n\n\n");
    // XXX: make sure the key ID references a key that was created
    // by the current origin
    log("aPlainText: " + aPlainText);

    let passphrase = this.enterPassphrase();
    // let passphrase = this.passphrase;
    log("passphrase: " + passphrase);
    log("aKeyID: " + aKeyID);
    if (!passphrase) {
      log("NO PASSPHRASE... BAILINGING OUT...");
      throw new Error("Nulltxt: No passphrase captured. Fatal error.");
    }
    let userIV =
      secretDecoderRing.decryptString(this.config.idIndex[aKeyID].iv);
    log("userIV: " + userIV);
    let userSalt =
      secretDecoderRing.decryptString(this.config.idIndex[aKeyID].salt);
    log("userSalt: " + userSalt);
    let userPrivKey = this.config.idIndex[aKeyID].privKey;

    worker.postMessage({ action: HIDE,
                         passphrase: passphrase,
                         iv: userIV,
                         salt: userSalt,
                         privKey: userPrivKey, // sender's private key
                         plainText: aPlainText,
                         pubKey: aPublicKey, // recipient's pub key
                         metaData: aMetaData,
                       });
  },

  show: function DCA_show(aCipherMessage, aKeyID, aMetaData, aPassphrase)
  {
    log("show()\n");
    // XXX: make sure the keyID references a key generated by the current origin

    log("metaData: ");
    pprint(aMetaData);
    log("cipherMessage");
    pprint(aCipherMessage);
    log("keyID: " + aKeyID);

    let passphrase = aPassphrase || this.enterPassphrase();

    let userIV =
      secretDecoderRing.decryptString(this.config.idIndex[aKeyID].iv);
    let userSalt =
      secretDecoderRing.decryptString(this.config.idIndex[aKeyID].salt);
    let userPrivKey = this.config.idIndex[aKeyID].privKey;
    let cipherMessage = XPCNativeWrapper.unwrap(aCipherMessage);

    worker.postMessage({ action: SHOW,
                         cipherContent: cipherMessage.content,
                         cipherWrappedKey: cipherMessage.wrappedKey,
                         cipherPubKey: cipherMessage.pubKey,
                         cipherIV: cipherMessage.iv,
                         passphrase: passphrase,
                         privKey: userPrivKey,
                         salt: userSalt,
                         iv: userIV,
                         signature: cipherMessage.signature,
                         metaData: aMetaData,
                       });
  },

  /**
   * Begin the generate keypair process
   *
   * 1. Prompt user for passphrase and confirm passphrase
   * 2. Pass the passphrase off to the worker to generate a keypair
   *
   * @returns void
   */
  beginGenerateKeypair: function DCM_beginGenerateKeypair(aWindowID, aRequestID)
  {
    // TODO: check if the user already has a keypair and confirm they
    // would like to overwrite it
    log("beginGenerateKeypair()");
    let win = this.getWindowByWindowId(aWindowID);
    log(win);
    let passphrase = {};
    let prompt =
      promptSvc.promptPassword(win,
                               getStr("enterPassphraseInitTitle"),
                               getStr("enterPassphraseInitText"),
                               passphrase, null, { value: false });
    if (prompt && passphrase.value) {
      let passphraseConfirm = {};
      let prompt =
        promptSvc.promptPassword(win,
                                 getStr("confirmPassphraseInitTitle"),
                                 getStr("confirmPassphraseInitText"),
                                 passphraseConfirm,
                                 null, { value: false });
      if (prompt && passphraseConfirm.value &&
          (passphraseConfirm.value == passphrase.value)) {
        this.generateKeypair(passphrase.value, aWindowID, aRequestID);
      }
      else {
        promptSvc.alert(win,
                        getStr("passphrasesDoNotMatchTitle"),
                        getStr("passphrasesDoNotMatchText"));
      }
    }
  },

  getWindowByWindowId: function getWindowByWindowId(aId) {
    let someWindow = Services.wm.getMostRecentWindow("navigator:browser");
    if (someWindow) {
      let windowUtils = someWindow.QueryInterface(Ci.nsIInterfaceRequestor)
        .getInterface(Ci.nsIDOMWindowUtils);
      return windowUtils.getOuterWindowWithId(aId);
    }
    return null;
  },

  /**
   * The internal 'generateKeypair' method that calls the worker
   *
   * @param string aPassphrase
   * @returns void
   */
  generateKeypair: function DCM_generateKeypair(aPassphrase, aWindowID, aRequestID)
  {
    log("generateKeypair()\n");
    log(aWindowID);
    log(aRequestID);
    worker.postMessage({ action: GENERATE_KEYPAIR,
                         passphrase: aPassphrase,
                         id: aWindowID,
                         requestID: aRequestID,
                       });
    this.passphraseCache.encryptedPassphrase = secretDecoderRing.encryptString(aPassphrase);
    this.passphraseCache.lastEntered = Date.now();
  },

  /**
   * The internal 'getPublicKey' method
   *
   * @returns void
   */
  // XXX: this is not available from the DOM in nulltxt
  getPublicKey: function DCM_getPublicKey(aCallback, aSandbox)
  {
    // Callbacks.register(GET_PUBLIC_KEY, aCallback, aSandbox);
    // TODO: need a gatekeeper function/prompt to allow access to your publicKey
    // TODO: looks like we can get this async via FileUtils
    // Callbacks.handleGetPublicKey(this.config.default.pubKey);
  },

  getPublicKeyByID: function DCM_getPublicKeyByID(aID)
  {
    if (!aID) {
      throw new Error("getPublicKeyByID: ID argument required");
    }
    try {
      let pubkey = this.config.idIndex[aID].pubKey;
      return pubkey;
    }
    catch (ex) {
      Cu.reportError("Cannot get public key by ID: " + aID);
      return null;
    }
  },

  getAllKeyDataByID: function DCM_getAllKeyDataByID(aID)
  {
    if (!aID) {
      throw new Error("getAllKeyDataByID: ID argument required");
    }
    try {
      let keydata = this.config.idIndex[aID];
      return keydata;
    }
    catch (ex) {
      Cu.reportError("Cannot get key data by ID: " + aID);
      return null;
    }
  },

  /**
   * The internal 'encrypt' method which calls the worker to do the encrypting
   *
   * @param string aPlainText
   * @param string aPublicKey
   * @returns void
   */
  encrypt: function DCM_encrypt(aPlainText, aPublicKey, aMetaData)
  {
    worker.postMessage({ action: ENCRYPT,
                         pubKey: aPublicKey,
                         plainText: aPlainText,
                         metaData: aMetaData,
                       });
  },

  /**
   * The internal 'decrypt' method which calls the worker to do the decrypting
   *
   * @param Object aCipherMessage
   * @param string aPassphrase [optional]
   * @returns void
   */
  decrypt:
  function DCM_decrypt(aCipherMessage, aPassphrase)
  {
    let passphrase = aPassphrase || this.enterPassphrase();

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
                         passphrase: passphrase,
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
    let passphrase;
    // check if the passphrase has ever been entered
    if (!this.passphraseCache.encryptedPassphrase) {
      passphrase = this.enterPassphrase();
    }
    // check if the passphrase is outdated and needs to be re-entered
    else if ((Date.now() - this.passphraseCache.lastEntered) > PASSPHRASE_TTL) {
      passphrase = this.enterPassphrase();
    }
    else {
      return secretDecoderRing.decryptString(this.passphraseCache.encryptedPassphrase);
    }
  },

  /**
   * Enter the passphrase via a prompt
   *
   * @returns void
   */
  enterPassphrase: function DCM_enterPassphrase()
  {
    log("enterPassphrase()\n");
    log("Cached passphrase???\n\n");
    log(this.passphraseCache.encryptedPassphrase);
    if (this.passphraseCache.encryptedPassphrase) {
      this.passphraseCache.lastEntered = Date.now();
      return secretDecoderRing.decryptString(this.passphraseCache.encryptedPassphrase);
    }

    // accept the passphrase and store it in memory - encrypted via SDR
    // remember the passphrase for 1 hour
    let passphrase = {};
    let prompt = promptSvc.promptPassword(this.xulWindow,
                                          getStr("enterPassphraseTitle"),
                                          getStr("enterPassphraseText"),
                                          passphrase, null, { value: false });
    if (passphrase.value) {
      log("passphrase.value: " + passphrase.value);
      // XXX !!!! TODO validate passphrase!!!
      this.passphraseCache.encryptedPassphrase =
        secretDecoderRing.encryptString(passphrase.value);
      this.passphraseCache.lastEntered = Date.now();
      return passphrase.value;
    }
    else {
      throw new Error(getStr("noPassphraseEntered"));
    }
  },

  /**
   * Make sure the passphrase is the one used to generate the keypair
   *
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  verifyPassphrase: function DCM_verifyPassphrase(aCallback, aSandbox)
  {
    // Callbacks.register(VERIFY_PASSPHRASE, aCallback, aSandbox);
    let passphrase = this.passphrase;
    let userPrivKey = this.config.default.privKey;
    let userIV = secretDecoderRing.decryptString(this.config.default.iv);
    let userSalt = secretDecoderRing.decryptString(this.config.default.salt);

    worker.postMessage({ action: VERIFY_PASSPHRASE,
                         privKey: userPrivKey,
                         passphrase: passphrase,
                         salt: userSalt,
                         iv: userIV
                       });
  },

  /**
   * Prompt the user for a passphrase to begin the decryption process
   *
   * @param object aCipherMessage
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  promptDecrypt: function DCM_promptDecrypt(aCipherMessage, aCallback, aSandbox)
  {
    // Callbacks.register(DECRYPT, aCallback, aSandbox);
    let passphrase = this.passphrase;

    if (passphrase) {
      this.decrypt(aCipherMessage, passphrase);
      return;
    }

    throw new Error(getStr("noPassphraseEntered"));
  },

  /**
   * Front-end 'sign' method prompts user for passphrase then
   * calls the internal _sign message
   *
   * @param string aPlainTextMessage
   * // @param function aCallback
   * // @param sandbox aSandbox
   * @returns void
   */
  sign: function DCM_sign(aPlainTextMessage)
  {
    // Callbacks.register(SIGN, aCallback, aSandbox);
    let passphrase = this.passphrase;
    if (passphrase) {
      this._sign(aPlainTextMessage, passphrase);
    }
    else {
      throw new Error(getStr("noPassphraseEntered"));
    }
  },

  /**
   * Internal backend '_sign' method calls the worker to do the actual signing
   *
   * @param string aPlainTextMessage
   * @param string aPassphrase
   * @returns void
   */
  _sign: function DCM__sign(aPlainTextMessage, aPassphrase)
  {
    let userIV = secretDecoderRing.decryptString(this.config.default.iv);
    let userSalt = secretDecoderRing.decryptString(this.config.default.salt);
    let userPrivKey = this.config.default.privKey;
    let hash = this._SHA256(aPlainTextMessage);

    worker.postMessage({ action: SIGN,
                         hash: hash,
                         passphrase: aPassphrase,
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

  generateSymKey: function DCM_generateSymKey(aCallback, aPublicKey, aSandbox)
  {
    // Callbacks.register(GENERATE_SYM_KEY, aCallback, aSandbox);

    var pubKey;
    if (!aPublicKey) {
      pubKey = this.config.default.pubKey;
    }
    else {
      pubKey = aPublicKey;
    }

    worker.postMessage({ action: GENERATE_SYM_KEY,
                         pubKey: pubKey
                       });
  },

  wrapKey: function DCM_wrapKey(aCipherObject, aPublicKey, aCallback, aSandbox)
  {
    // unwrap then re-wrap the symmetric key inside aCipherObject, return a new
    // cipherObject that can be unlocked by another keypair
    // Callbacks.register(WRAP_SYM_KEY, aCallback, aSandbox);

    let passphrase = this.passphrase;
    var userIV = secretDecoderRing.decryptString(this.config.default.iv);
    var userSalt = secretDecoderRing.decryptString(this.config.default.salt);
    var userPrivKey = this.config.default.privKey;

    var cipherObj = XPCNativeWrapper.unwrap(aCipherObject);
    var cipherText = null;
    if (cipherObj.cipherText) {
      cipherText = cipherObj.cipherText;
    }

    worker.postMessage({ action: WRAP_SYM_KEY,
                         // cipherObject: cipherObj,
                         cipherText: cipherText,
                         cipherWrappedKey: cipherObj.wrappedKey,
                         cipherPubKey: cipherObj.pubKey,
                         cipherIV: cipherObj.iv,
                         iv: userIV,
                         salt: userSalt,
                         privKey: userPrivKey,
                         passphrase: passphrase,
                         pubKey: aPublicKey
                       });
  },

  /**
   * SymEncrypt (symmetric)
   * @param string aPlaintext
   * @param string aPublicKey
   * @param function aCallback
   * @param sandbox aSandbox
   * @returns void
   */
  symEncrypt: function DCM_SymEncrypt(aPlainText, aPublicKey, aCallback, aSandbox)
  {
    // Callbacks.register(SYM_ENCRYPT, aCallback, aSandbox);

    var pubKey;
    if (!aPublicKey) {
      pubKey = this.config.default.pubKey;
    }
    else {
      pubKey = aPublicKey;
    }

    worker.postMessage({ action: SYM_ENCRYPT,
                         plainText: aPlainText,
                         pubKey: pubKey
                       });
  },

  symDecrypt:
  function DCM_SymDecrypt(aCipherObject, aCallback, aSandbox)
  {
    var passphrase = this.passphrase; // this getter will throw if nothing entered
    var userIV = secretDecoderRing.decryptString(this.config.default.iv);
    var userSalt = secretDecoderRing.decryptString(this.config.default.salt);
    var userPrivKey = this.config.default.privKey;

    // Callbacks.register(SYM_DECRYPT, aCallback, aSandbox);

    var cipherObj = XPCNativeWrapper.unwrap(aCipherObject);

    worker.postMessage({ action: SYM_DECRYPT,
                         // cipherObject: cipherObj,
                         // XXX: work around for bug 667388
                         cipherText: cipherObj.cipherText,
                         cipherWrappedKey: cipherObj.wrappedKey,
                         cipherPubKey: cipherObj.pubKey,
                         cipherIV: cipherObj.iv,
                         iv: userIV,
                         salt: userSalt,
                         privKey: userPrivKey,
                         passphrase: passphrase
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
    // Callbacks.register(SHA256, aCallback, aSandbox);
    // let hash = this._SHA256(aPlainText);
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
    log("configurationFile()");
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
};

/**
 * Initialize the DOMCryptMethods object by getting the configuration object
 * and creating the callbacks object
 * @param outparam aDOMCrypt
 * @returns void
 */
function initializeDOMCrypt()
{
  log("InitializeDOMCrypt()");
  // Full path to NSS via js-ctypes
  let path = Services.dirsvc.get("GreD", Ci.nsILocalFile);
  let libName = ctypes.libraryName("nss3"); // platform specific library name
  path.append(libName);
  let fullPath = path.path;

  let fileCreated = {};
  let file = DOMCryptMethods.configurationFile(fileCreated);
  if (fileCreated.value) {
    log("config file created......");
    let config = {idIndex: {}};
    DOMCryptMethods.config = config;
    writeConfig(file, JSON.stringify(config), function writeCallback() {
      log("Initial config written to disk...");
      DOMCryptMethods.init(config, fullPath);
    });
    return;
  }

  loadConfig(file, function loadCallback(aData) {
    log("Config Object loaded: ");
    pprint(aData);
    DOMCryptMethods.init(aData, fullPath);
  });
}

function writeConfig(aFile, aData, aCallbak) {
  // Initialize the file output stream.
  let ostream = FileUtils.openSafeFileOutputStream(aFile);

  // Obtain a converter to convert our data to a UTF-8 encoded input stream.
  let converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"]
                    .createInstance(Ci.nsIScriptableUnicodeConverter);
  converter.charset = "UTF-8";

  // Asynchronously copy the data to the file.
  let istream = converter.convertToInputStream(aData);
  NetUtil.asyncCopy(istream, ostream, function(rc) {
    if (aCallbak)
      aCallbak();
  });
}

// loadConfig
function loadConfig(aFile, aCallback) {
  log("loadConfig()");
  try {
    let channel = NetUtil.newChannel(aFile);
    channel.contentType = "application/json";
    NetUtil.asyncFetch(channel, function(aStream, aResult) {
      if (!Components.isSuccessCode(aResult)) {
        Cu.reportError("NulltxtMehods.jsm: Could not read from json file "
                       + aFile.path);
        if (aCallback) {
          aCallback(null);
        }
        return;
      }
      // Read json file into a string
      let data = null;
      try {
        // Obtain a converter to read from a UTF-8 encoded input stream.
        let converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"]
                          .createInstance(Ci.nsIScriptableUnicodeConverter);
        converter.charset = "UTF-8";

        data =
          JSON.parse(converter.
                     ConvertToUnicode(NetUtil.
                                      readInputStreamToString(aStream,
                                                              aStream.available()) || ""));
        aStream.close();
        if (aCallback) {
          aCallback(data);
        }
      } catch (ex) {
        Cu.reportError("NulltxtMethods: Could not parse JSON: " +
                       aFile.path + " " + ex);
        if (aCallback) {
          aCallback(null);
        }
      }
    });
  }
  catch (ex) {
    Cu.reportError("NulltxtMethods: Could not read from " +
                     aFile.path + " : " + ex);
    if (aCallback) {
      aCallback(null);
    }
  }
}

initializeDOMCrypt();

var NulltxtMethods = DOMCryptMethods;

function CryptoConsole(aWindowID, aDOMReqID)
{
  this._domReqID = aDOMReqID || null;
  this._windowID = aWindowID;
  // find the window...
  let win = this.getWindowByWindowId(aWindowID);
  if (win) {
    this.buildUI(win);
  }
  else {
    let err = "CryptoConsole: Cannot get Window by ID: " + aWindowID;
    Cu.reportError(err);
    throw new Error(err);
  }
  this.idle = true;
}

CryptoConsole.prototype = {
  buildUI: function cc_buildUI(aWindow)
  {
    log("buildUI()");
    // XXX: check to see what verison of Firefox we are running in, change the UI
    // based on this
    // get the outer chromeWindow
    // need to prepend the UI box into #appcontent
    let chromeWin = this.getChromeWindowFromDOM(aWindow);
    let gBrowser = chromeWin.gBrowser;
    this.ownerDoc = gBrowser.ownerDocument;
    let browser = this.getBrowserForContentWindow(gBrowser, aWindow);
    // we need to attach the UI nodes above the browser
    let splitterNode = this.makeSplitterNode();
    let uiNode = this.makeUINode();
    // 4th parent is the notificationBox that holds the browser:
    // let nBox = browser.parentNode.parentNode.parentNode.parentNode;
    let nBox = gBrowser.getNotificationBox(browser);
    log("nBox.id: " + nBox.getAttribute("id"));
    // insert the UI nodes as first and second children
    nBox.appendChild(splitterNode);
    nBox.appendChild(uiNode);
  },

  destroyUI: function cc_destroyUI()
  {
    this.mainBox.parentNode.removeChild(this.splitter);
    this.mainBox.parentNode.removeChild(this.mainBox);
  },

  makeSplitterNode: function cc_makeSplitterNode()
  {
    this.splitter = this.ownerDoc.createElement("splitter");
    // this.splitter.setAttribute("class", "devtools-horizontal-splitter");
    this.splitter.setAttribute("collapse", "after");
    let grippy = this.ownerDoc.createElement("grippy");
    this.splitter.appendChild(grippy);
    return this.splitter;
  },

  updateUI: function cc_updateUI(aView, aMessage)
  {
    log("updateUI()");
    this._message = aMessage;

    switch (aView) {
    case "init":
      this.initComplete(aMessage);
      break;
    case "read":
      this.readUI();
      break;
    case "write":
      this.writeUI();
      break;
    case "pubKey":
      this.pubKeyUI();
      break;
    case "contacts":
      this.contactsUI();
      break;
    default:
      break;
    }
  },

  makeDeck: function cc_makeDeck()
  {
    log("makeDeck()");
    this.uiDeck = this.ownerDoc.createElement("deck");
    this.uiDeck.setAttribute("selectedIndex", 0);
    return this.uiDeck;
  },

  makeGenericBox: function cc_makeGenericBox(aConfig)
  {
    log("makeGenericBox()");
    this[aConfig.nodeName] = {};
    let vbox = this.ownerDoc.createElement("vbox");
    this[aConfig.nodeName].vbox = vbox;
    // need textarea and button
    let textBox = this.ownerDoc.createElement("textbox");
    textBox.setAttribute("readonly", true);
    textBox.setAttribute("multiline", true);
    textBox.setAttribute("cols", 80);
    textBox.setAttribute("rows", 10);
    textBox.setAttribute("id", aConfig.textBoxID);
    this[aConfig.nodeName].textBox = textBox;

    let statusLabel = this.ownerDoc.createElement("label");
    statusLabel.setAttribute("value", "Status");
    this[aConfig.nodeName].statusLabel = statusLabel;

    let statusText = this.ownerDoc.createElement("textbox");
    statusText.setAttribute("value", "Ready");
    statusText.setAttribute("disabled", true);
    this[aConfig.nodeName].statusText = statusText;

    let buttonBox = this.ownerDoc.createElement("hbox");
    buttonBox.setAttribute("flex", 1);

    let button = this.ownerDoc.createElement("button");
    button.setAttribute("label", aConfig.buttonLabel);
    button.setAttribute("flex", 1);
    this[aConfig.nodeName].button = button;

    let closeButton = this.ownerDoc.createElement("button");
    closeButton.setAttribute("label", "Close");
    closeButton.setAttribute("flex", 1);
    this[aConfig.nodeName].closeButton = closeButton;
    closeButton.setAttribute("oncommand", "nulltxtUI.closeUI(this, " +
                                          this._windowID  + ")");

    let buttonID;

    switch (aConfig.textBoxID) {
    case "write-box":
      button.setAttribute("oncommand", "nulltxtUI.encryptMessageText(this, " +
                                       this._windowID  + ")");
      buttonID = "encrypt-button-" + this._windowID;
      break;
    case "read-box":
      button.setAttribute("oncommand", "nulltxtUI.decryptCipherMessage(this, " +
                                       this._windowID  + ")");
      buttonID = "decrypt-button-" + this._windowID;
    default:
      break;
    }

    button.setAttribute("id", buttonID);

    buttonBox.appendChild(button);
    buttonBox.appendChild(closeButton);

    let label = this.ownerDoc.createElement("label");
    label.setAttribute("control", aConfig.textBoxID);
    label.setAttribute("value", aConfig.labelValue);
    this[aConfig.nodeName].label = label;

    vbox.appendChild(label);
    vbox.appendChild(textBox);
    vbox.appendChild(statusLabel);
    vbox.appendChild(statusText);
    vbox.appendChild(buttonBox);
    return vbox;
  },

  makeUINode: function cc_makeUINode()
  {
    log("makeUINode()");
    // XXX: Maybe?? want this to be an iframe that loads a chrome url,
    // in which case we will be able to declaratively define the UI, meh.
    let mainBox = this.ownerDoc.createElement("hbox");
    this.mainBox = mainBox;
    this._mainID = this.nodeIDPrefix + "main-box";
    mainBox.setAttribute("id", this._mainID);
    mainBox.setAttribute("class", "devtools-toolbar");

    let self = this;

    let readBox = this.makeGenericBox({
      textBoxID: "read-box",
      buttonLabel: "Decrypt",
      labelValue: "Read",
      buttonCommand: "",
      nodeName: "readBox",
    });

    let writeBox = this.makeGenericBox({
      textBoxID: "write-box",
      buttonLabel: "Encrypt",
      labelValue: "Write",
      buttonCommand: "",
      nodeName: "writeBox",
    });

    let pubKeyBox = this.makeGenericBox({
      textBoxID: "pub-key-box",
      buttonLabel: "Save to Clipboard",
      labelValue: "Your Public Key is below:",
      buttonCommand: "",
      nodeName: "publicKeyBox",
    });

    let deck = this.makeDeck();
    deck.appendChild(pubKeyBox);
    deck.appendChild(readBox);
    deck.appendChild(writeBox);
    deck.selectedIndex = 0;
    mainBox.appendChild(deck);
    this.uiOpen = true;
    return mainBox;
  },

  initComplete: function cc_initComplete(aMessage, aKeyID)
  {
    log("initComplete()");
    pprint(aMessage);
    // this.topLabel.setAttribute("value", "Initialization Complete: Your Public Key is:");
    // this.readTextBox.setAttribute("value", NulltxtMethods.config.default.pubKey);
    // this.decryptButton.disabled = true;
    // this.decryptButton.setAttribute("label", "");
    this.uiDeck.selectedIndex = 0;
    this.publicKeyBox.label.setAttribute("value",
                                    "Initialization Complete: Your Public Key is:");
    // get the key data:
    let pubkey = NulltxtMethods.getPublicKeyByID(aKeyID);

    this.publicKeyBox.textBox.setAttribute("value", pubkey);
    // XXX: need to fireSuccess with the pubkey data and ID
  },

  pubKeyUI: function cc_pubKeyUI()
  {
    log("pubKeyUI()");
    this.uiDeck.setAttribute("selectedIndex", 0);
    this.publicKeyBox.label.setAttribute("value",
                                    "Your Public Key is:");
    this.publicKeyBox.textBox.setAttribute("value",
                                      NulltxtMethods.config.default.pubKey);
  },

  readUI: function cc_readUI()
  {
    log("readUI()");
    this.uiDeck.setAttribute("selectedIndex", 1);
    this.readBox.label.setAttribute("value",
                                     "Verify, Decrypt and Read a message from: " +
                                     this._message.authorName || "");
    this.readBox.statusLabel.setAttribute("value", "Signature");
    this.readBox.statusText.setAttribute("value", this._message.signature || "");
    this.readBox.textBox.setAttribute("value",
                                       this._message.content);
  },

  writeUI: function cc_writeUI()
  {
    log("writeUI()");
    log("selectedIndex: " + this.uiDeck.selectedIndex);
    this.uiDeck.setAttribute("selectedIndex", 2);
    log(this.writeBox);
    this.writeBox.label.setAttribute("value",
                                     "Write text to: " +
                                     this._message.recipientName);
    this.writeBox.textBox.setAttribute("value",
                                       this._message.content || "");
    this.writeBox.statusLabel.setAttribute("value", "Signature");
    this.writeBox.statusText.setAttribute("value", this._message.signature || "");
    this.writeBox.textBox.removeAttribute("readonly");
  },

  get nodeIDPrefix() {
    return "crypto-console-" + this._windowID + "-";
  },

  getChromeWindowFromDOM: function cc_getChromeWindowFromDOM(aWindow)
  {
    var chromeWin = aWindow
      .QueryInterface(Ci.nsIInterfaceRequestor)
      .getInterface(Ci.nsIWebNavigation)
      .QueryInterface(Ci.nsIDocShellTreeItem)
      .rootTreeItem
      .QueryInterface(Ci.nsIInterfaceRequestor)
      .getInterface(Ci.nsIDOMWindow)
      .QueryInterface(Ci.nsIDOMChromeWindow);
    return chromeWin;
  },

  getWindowByWindowId: function getWindowByWindowId(aId) {
    let someWindow = Services.wm.getMostRecentWindow("navigator:browser");
    if (someWindow) {
      let windowUtils = someWindow.QueryInterface(Ci.nsIInterfaceRequestor)
        .getInterface(Ci.nsIDOMWindowUtils);
      return windowUtils.getOuterWindowWithId(aId);
    }
    return null;
  },

  getBrowserForContentWindow:
  function cc_getBrowserforContentWindow(aGBrowser, aContentWindow)
  {
    log("getBrowserForContentWindow()");
    let browsers = aGBrowser.browsers;
    for (let browser of browsers) {
      if (browser.contentWindow == aContentWindow) {
        log("browser: " + browser);
        log("browser.contentWindow.location: " + browser.contentWindow.location);
        return browser;
      }
    }
    return null;
  },

  handleMessage: function cc_handleMessage(aMessage)
  {
    log("handleMessage()\n");
    pprint(aMessage);
    if (this.idle && this.uiOpen) {
      // we can open this message in the UI
      this._message = aMessage;
      this._domReqID = aMessage._domReqID; // the UI depends on this being
      // set to reliably retrun the content success handler

      switch (aMessage.type) {
      case "read":
        this.updateUI("read", aMessage);
        break;
      case "write":
        this.updateUI("write", aMessage);
        break;
      case "contact":
        this.updateUI("contacts", aMessage);
        break;
      case "verify":
        this.updateUI("verify", aMessage);
        break;
      case "sign":
        this.updateUI("sign", aMessage);
      case "keygen":
        log("case keygen...");
        this.updateUI("keygen", aMessage);
        break;
      default:
        break;
      }
    }
    else {
      this.queue.push(aMessage);
    }
  },

  displayDecryptedText: function cc_displayDecryptedText(aText, aVerified)
  {
    this.readTextBox.setAttribute("value", aText);
    // XXX: Need to display a new button for ('reply')
    // XXX: 'Reply' step assumes the user edits the text,
    //       a. selects a contact(s) to receive the message,
    //       b. encrypts the data
    //       c. triggers a DOMRequest.fireSuccess to pass the
    //          cipherMessage back to the document
    // XXX: Need to indicate the message was verified
  },

  // A Queue of cipherObjects to process
  queue: [],
};

function supportsString(aString)
{
  let str = Cc["@mozilla.org/supports-string;1"].
    createInstance(Ci.nsISupportsString);
  str.data = aString;
  return str;
}
