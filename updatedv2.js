"use strict";

const Jose = require("datapower-jose");
const debug = require("debug")("datapower:visa:controller");

async function decryptData(body) {
  const privKey = context.file.read("keys/maybank-private.pem", "base64");

  const encryptedPayload = typeof body === "string" ? JSON.parse(body) : body;

  const keystore = new Jose.JWK.KeyStore();
  keystore.add(privKey, "pem");

  const decProps = {
    kid: encryptedPayload.header.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };

  const decrypter = await Jose.JWE.createDecrypt(keystore, decProps);
  const decryptedPayload = await decrypter.decrypt(encryptedPayload);
  const plaintext = decryptedPayload.payload.toString();
  debug("Decrypted data: %s", plaintext);

  return decryptedPayload;
}

async function encryptData(body) {
  const pubKey = context.file.read("keys/visa-public.pem", "base64");

  const keystore = new Jose.JWK.KeyStore();
  keystore.add(pubKey, "pem");

  const iat = Date.now();

  const encProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };

  const encrypter = await Jose.JWE.createEncrypt(
    keystore,
    {
      fields: {
        enc: "A128GCM",
        iat: iat,
      },
    },
    encProps
  );

  const encryptedPayload = await encrypter
    .update(JSON.stringify(body.Input))
    .final();

  debug("Encrypt data successful");

  return {
    JWEHeader: {
      alg: "RSA-OAEP-256",
      enc: "A128GCM",
      iat: iat,
      kid: body.JWEHeader.kid,
    },
    Output: encryptedPayload,
  };
}

module.exports = {
  decryptData,
  encryptData,
};
