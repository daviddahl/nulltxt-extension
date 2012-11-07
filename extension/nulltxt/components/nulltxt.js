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
let Cr = Components.results;

function log(aMessage) {
  var _msg = "Nulltxt: " + aMessage + "\n";
  dump(_msg);
}

function pprint(aObj)
{
  if (typeof aObj == "object") {
    for (let prop in aObj) {
      log(prop + ": " + aObj[prop]);
    }
  }
  else {
    log(aObj);
  }
}

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/DOMRequestHelper.jsm");
Cu.import("resource://gre/modules/ObjectWrapper.jsm");
Cu.import("resource://nulltxt/NulltxtMethods.jsm"); // XXX: need to run this from main thread perhaps via another component that is instaciated on profile change
Cu.import("resource://gre/modules/ObjectWrapper.jsm");

function getWindowByWindowId(aId) {
  let someWindow = Services.wm.getMostRecentWindow("navigator:browser");
  if (someWindow) {
    let windowUtils = someWindow.QueryInterface(Ci.nsIInterfaceRequestor)
      .getInterface(Ci.nsIDOMWindowUtils);
    return windowUtils.getOuterWindowWithId(aId);
  }
  return null;
}

XPCOMUtils.defineLazyServiceGetter(this, "cpmm",
                                   "@mozilla.org/childprocessmessagemanager;1",
                                   "nsIMessageSender");

XPCOMUtils.defineLazyGetter(this, "Addressbook", function (){
    Cu.import("resource://nulltxt/addressbookManager.js");
    return addressbook;
});

const kCIPHER_OBJ_TYPE = {
  verify: 0,     // Verify a signature
  read: 1,       // Read an encrypted message
  contacts: 2,   // Add a publickey to the browser contacts
  write: 3,      // Begin writing plain text to a contact,
  keygen: 4,
};

const kCIPHER_OBJ_FORMAT = {
  DER_BASE64: 0,
  JSON: 1,
};

function Nulltxt() {}

Nulltxt.prototype = {
  __proto__: DOMRequestIpcHelper.prototype,
  classID: Components.ID("{249d0520-cf75-4f6c-9b5c-600bce80b544}"),

  QueryInterface: XPCOMUtils.generateQI([Ci.nsIDOMGlobalPropertyInitializer,
                                         Ci.nsIObserver,]),
  classInfo: XPCOMUtils.generateCI({classID: Components.ID("{249d0520-cf75-4f6c-9b5c-600bce80b544}"),
                                    contractID: "@nulltxt.se/bridge;1",
                                    flags: Ci.nsIClassInfo.DOM_OBJECT,
                                    classDescription: "nulltxt bridge"}),
  _id: 0,

  _window: null,

  init: function nc_init(aWindow)
  {
    this.initHelper(aWindow, [
                              "Bridge:UI:RegisterCipherObject",
                              "Bridge:UI:Initialize",
                             ]);
    cpmm.sendAsyncMessage("Bridge:RegisterForMessages",
                          [
                            "Bridge:RegisterCipherObject",
                          ]);

    cpmm.addMessageListener("Bridge:UI:CipherObjectRegistered", this);
    cpmm.addMessageListener("Bridge:UI:InitializationComplete", this);
    cpmm.addMessageListener("Bridge:UI:CipherObjectReturned", this);

    let util = this._window.QueryInterface(Ci.nsIInterfaceRequestor).
                 getInterface(Ci.nsIDOMWindowUtils);
    this._id = util.outerWindowID;

    let self = this;

    let bridgeAPI = {
      getCipherObject: self.getCipherObject.bind(self),

      initialize: self.initialize.bind(self),

      __exposedProps__:
      {
        getCipherObject: "r",
        initialize: "r",
      }
    };

    return bridgeAPI;
  },

  initialize: function nt_initialize()
  {
    log("nt_initialize()");
    let request = this.createRequest();
    let requestID = this.getRequestId(request);
    let self = this;
    log("sendAsyncMessage(Bridge:UI:Initialize)");
    cpmm.sendAsyncMessage("Bridge:UI:Initialize", { id: self._id });
    return request;
  },

  getCipherObject: function nt_getCipherObject(aCipherObject)
  {
    // creates a DOMRequest, etc
    let request = this.createRequest();
    let requestID = this.getRequestId(request);
    log("REQUEST ID GENERATED: " + requestID);
    // validate Object
    if (!(aCipherObject.type in kCIPHER_OBJ_TYPE &&
        aCipherObject.format in kCIPHER_OBJ_FORMAT)) {
      let err = "navigator.bridge.getCipherObject: Cipher object type or format label unsupported";
      Cu.reportError(err);
      throw new Error(err);
    }
    // Get the current Window ID
    // open browser chrome UI where we can decrypt the message and display it.
    aCipherObject._windowID = Number(this._id);
    aCipherObject._domReqID = requestID;
    log("window ID: " + aCipherObject._windowID);

    // XXX: make sure any read or write operation also has a "keyID" property in the cipher Object!!

    try {
      log("sending async message: Bridge:UI:RegisterCipherObject");
      cpmm.sendAsyncMessage("Bridge:UI:RegisterCipherObject", aCipherObject);
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
    }
    return request;
  },

  receiveMessage: function receiveMessage(aMessage)
  {
    log("receiveMessage()");
    log("\n\n");
    log("requestID" + aMessage.requestID);
    pprint(aMessage.json);
    log("metaData...............");
    pprint(aMessage.json.metaData);
    var msg = aMessage.json;
    let req;
    let winID = aMessage.json.metaData.windowID;
    let window = getWindowByWindowId(winID);
    try {
      req = this.takeRequest(aMessage.json.metaData.domReqID);
      log("domReqID: " + aMessage.json.metaData.domReqID);
    }
    catch (ex) {
      log(ex);
      log(ex.stack);
      req = this.takeRequest(msg.requestID);
      log("requestID: " + msg.requestID);
    }    log("\n\nreq\n\n");
    pprint("req: " + req);

    // if ((msg.oid != this._id || !req))
    //  return;

    // XXX: make sure to handle Error Conditions, fireError, etc...

    switch (aMessage.name) {
    case "Bridge:OperationComplete":
      Services.DOMRequest.fireSuccess(req, aMessage);
      break;
    case "Bridge:OperationFailed":
      Services.DOMRequest.fireError(req, msg.error);
      break;
    case "Bridge:UI:CipherObjectRegistered":
      Services.DOMRequest.fireSuccess(req, aMessage);
      break;
    case "Bridge:UI:CipherObjectReturned":
      log("CipherObjectReturned...");
      let _obj;
      if (msg.action == "dataShown") {
        let chromeObj = {
          verification: msg.verification,
        };
        _obj = ObjectWrapper.wrap(chromeObj, window);
      }
      else if (msg.action == "keypairGenerated") {
        let chromeObj = {
          publicKey: msg.publicKey,
          id: msg.id,
        };
        _obj = ObjectWrapper.wrap(chromeObj, window);
      }
      else if (msg.action == "dataHidden") {
        _obj = ObjectWrapper.wrap(msg.cipherMessage, window);
      }

      log("_obj ...............................");
      pprint(_obj);
      try {
        Services.DOMRequest.fireSuccess(req, _obj);
      }
      catch (ex) {
        log(ex);
        log(ex.stack);
      }
      break;
    case "Bridge:UI:InitializationComplete":
      Services.DOMRequest.fireSuccess(req, aMessage);
      break;
    default:
      break;
    }
  },
};

let NSGetFactory = XPCOMUtils.generateNSGetFactory([Nulltxt]);
