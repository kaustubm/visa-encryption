"use strict";

var Jose = require("jose");

function decryptData(body) {
  var privKey = context.file.read("keys/maybank-private.pem", "base64");

  var encryptedPayloadString = body;
  var encryptedPayload =
    typeof encryptedPayloadString == "string"
      ? JSON.parse(encryptedPayloadString)
      : encryptedPayloadString;

  var keystore = Jose.createKeyStore();

  var decProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };

  var decryptionKey = privKey;
  return keystore.add(decryptionKey, "pem", decProps).then(function (key) {
    return Jose.JWE.createDecrypt(key)
      .decrypt(encryptedPayload.Input)
      .then(function (result) {
        var plaintext = Buffer.from(result.plaintext, "base64").toString();
        debug("Decrypted data: %s", plaintext);
        return result;
      });
  });
}

function encryptData(body) {
  var pubKey = context.file.read("keys/visa-public.pem", "base64");

  var keystore = Jose.createKeyStore();

  var iat = Date.now();

  var encProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };

  var encryptionCert = pubKey;
  return keystore
    .add(encryptionCert, "pem", encProps)
    .then(function (key) {
      return Jose.JWE.createEncrypt(
        {
          format: "compact",
          fields: {
            enc: "A128GCM",
            iat: iat,
          },
        },
        key
      )
        .update(JSON.stringify(body.Input))
        .final()
        .then(function (result) {
          debug("Encrypt data successful");
          return {
            JWEHeader: {
              alg: "RSA-OAEP-256",
              enc: "A128GCM",
              iat: iat,
              kid: body.JWEHeader.kid,
            },
            Output: result,
          };
        });
    })
    .catch(function (err) {
      debug("Failed to encrypt data: %s", err.message);
      throw err;
    });
}

module.exports = {
  decryptData: decryptData,
  encryptData: encryptData,
};
