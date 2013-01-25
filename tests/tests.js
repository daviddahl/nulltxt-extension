// demo code
function browserSupport()
{
  try {
    window.navigator.bridge.getCipherObject;
  }
  catch (ex) {
    var err = "nulltxt extension is not installed!";
    alert(err);
    throw(err);
  }
}

function keygen(aName, id)
{
  var cipherObj = {
    type: "keygen",
    format: "DER_BASE64"
  };

  var request = window.navigator.bridge.getCipherObject(cipherObj);

  request.onsuccess = function ()
  {
    var _id = "#pub-key-" + id;
    $(_id).text(this.result.publicKey);
    var _id2 = "#pub-key-" + id + "-ID";
    $(_id2).text(this.result.id);
  };

  request.onerror = function (error)
  {
    throw new Error(error);
    console.log(error.name);
  };
}

function writeOneToTwo()
{
  var writeCipherObject = {
    type: "write",
    format: "DER_BASE64",
    recipientName: "2",
    publicKey: $("#pub-key-2").text(),
    keyID: $("#pub-key-1-ID").text()
  };

  var request = window.navigator.bridge.getCipherObject(writeCipherObject);

  request.onsuccess = function ()
  {
    console.log(this.result);
    $("#cipher-obj-1").text(btoa(JSON.stringify(this.result)));
  };

  request.onerror   = function (aError)
  {
    console.error(aError.name);
    alert(aError.name);
  };
}


function readTwoFromOne()
{
  var readCipherObject = JSON.parse(atob($("#cipher-obj-1").text()));

  console.log("readCipherObject");
  console.log(readCipherObject);

  readCipherObject.type = "read";
  readCipherObject.format = "DER_BASE64";
  readCipherObject.authorName = "1";
  readCipherObject.keyID = $("#pub-key-2-ID").text();

  var request = window.navigator.bridge.getCipherObject(readCipherObject);

  request.onsuccess = function ()
  {
    console.log("Message decrypted, must be read in Browser UI");
    console.log(this.result);
    console.log("KNOWN BUG: verification is: " + this.result.verification);
  };

  request.onerror = function (aError)
  {
    console.log(aError.name);
  };
}
