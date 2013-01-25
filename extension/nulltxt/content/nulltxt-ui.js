/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Author: David Dahl <ddahl@mozilla.com>
 *
 * */

let Cu = Components.utils;
let Ci = Components.interfaces;
let Cc = Components.classes;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://nulltxt/NulltxtMethods.jsm");

const DEBUG = false;

function log(aMessage) {
  if (!DEBUG) {
    return;
  }
  var _msg = "*** nulltxt-ui: " + aMessage + "\n";
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

log("\n\nNULLTX UI LOADED\n\n");

let nulltxtUI = {
  test: function ntui_test()
  {
    Cu.reportError("TEST!!!!");
  },

  observe: function ntui_observe(aSubject, aTopic, aData)
  {
    // aData is the window ID
    switch (aTopic) {
    case "pubkey-encryption-finished":
      // at this point we need to clean up the UI
      this.UICleanUp("encrypt", aData);
      break;
    default:
      break;
    }
  },

  encryptMessageText:
  function ntui_encryptMessageText(aButtonElement, aWindowID)
  {
    log("ntui_encryptMessageText\n");
    let ui = NulltxtMethods.UIWidgets[aWindowID];
    let plainTxt = ui.writeBox.textBox.value;
    log("plainTxt: " + plainTxt);
    // We need the recipient's public key...
    let pubKey = ui._message.publicKey;
    let keyID = ui._message.keyID;
    let recipient = ui._message.publicKey;
    let domReqID = ui._domReqID;
    let metaData = {
      recipient: recipient,
      windowID: aWindowID,
      domReqID: domReqID,
    };
    NulltxtMethods.hide(plainTxt, pubKey, keyID, metaData);
    // This calls the worker, does the crypto on a thread and
    // returns the cipherMessage to the NulltxtMethods object
  },

  decryptCipherMessage:
  function ntui_decryptCipherMessage(aButtonElement, aWindowID)
  {
    let ui = NulltxtMethods.UIWidgets[aWindowID];
    let cipherMessage = ui._message;
    let domReqID = ui._domReqID;
    let metaData = {
      windowID: aWindowID,
      domReqID: domReqID,
    };
    NulltxtMethods.show(cipherMessage,
                        cipherMessage.keyID,
                        metaData,
                        null);
    // disable this button...
    aButtonElement.setAttribute("disabled", true);
  },

  closeUI: function ntui_closeUI(aButtonElement, aWindowID)
  {
    NulltxtMethods.removeUI(aWindowID);
  },

  UICleanUp: function ntui_uiCleanup(aView, aWindowID)
  {
    log("UICleanup()" + aView);
    // tell the CryptoConsole to reset the view
  },
};
