// demo code
function browserSupport()
{
  try {
    window.navigator.bridge.getCipherObject;
    $("#warning").hide();
  }
  catch (ex) {
    $("#warning").show();
  }
}

function keygen()
{
  var cipherObj = {
    type: "keygen",
    format: "DER_BASE64"
  };

  var request = window.navigator.bridge.getCipherObject(cipherObj);

  request.onsuccess = function ()
  {
    window._pubKey = this.result.publicKey;
    window._keyID = this.result.id;
    var html = "<h4>" +
      this.result.id + "</h4>"
      + "<h4>"
      + this.result.publicKey
      + "</h4>";
    $("#keygen").append($(html));
    console.log(this.result);
    $("#section-encrypt").show();
  };

  request.onerror = function (error)
  {
    alert(error.name);
    console.log(error.name);
  };
}

function write()
{
  var writeCipherObject = {
    type: "write",
    format: "DER_BASE64",
    recipientName: "drzhivago",
    publicKey: window._pubKey,
    keyID: window._keyID,
    // PREFILLED CONTENT FOR DEMO PURPOSES ONLY, THIS 'FEATURE' WILL BE REOMVED BEFORE ANY KIND OF RELEASE IS PUBLISHED
    content: "THE  rue  du Coq  d'Or, Paris,  seven in the  morning. A succession of furious,  choking yells  from the street. Madame Monce, who kept the little hotel opposite mine, had come out on to the pavement to address a lodger on the third floor. Her bare feet were stuck into sabots and her grey hair was streaming down. \nMADAME MONCE: ‘SALOPE! SALOPE! How many times have I told you not tosquash bugs on the wallpaper? Do you think you’ve bought the hotel, eh? Whycan’t you throw them out of the window like everyone else? PUTAIN! SALOPE!’\nTHE WOMAN ON THE THIRD FLOOR: ‘VACHE!’\nThereupon a whole variegated chorus of yells, as windows were flung open on every side and half the street joined in the quarrel. They shut up abruptly ten minutes later, when a squadron of cavalry rode past and people stopped shouting to look at them."
  };

  var request = window.navigator.bridge.getCipherObject(writeCipherObject);

  request.onsuccess = function ()
  {
    window._cipherObj = this.result;
    $("#writebox").text(this.result.content);
    $("#signature").text(this.result.signature);
    $("#raw-object").text(JSON.stringify(this.result, undefined, 2));
    $("#section-decrypt").show();
    window.location = "#decryption";
  };

  request.onerror   = function (aError)
  {
    console.log(aError.name);
  };
}

function read()
{
  if (!window._cipherObj) {
    alert("Run the 'Write' demo before 'Read'");
    throw new Error("Abort 'read'. No cipher object to operate on.");
  }
  var readCipherObject = window._cipherObj;
  readCipherObject.type = "read";
  readCipherObject.format = "DER_BASE64";
  readCipherObject.authorName = "drzhivago";
  readCipherObject.keyID = window._keyID;

  var request = window.navigator.bridge.getCipherObject(readCipherObject);

  request.onsuccess = function ()
  {
    console.log("Message decrypted, must be read in Browser UI");
    console.log(this.result);
    $("#verified-signature").text(this.result.verification);
  };

  request.onerror = function (aError)
  {
    console.log(aError.name);
  };
}

function sign()
{

}

function verify()
{

}

function hash()
{

}

