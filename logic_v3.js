const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const fs = require("fs");
const nodeJose = require("node-jose");
const path = require("path");
const moment = require("moment");

// Logger module
const Logger = require("./common/components/logger/index.js");
const logger = new Logger("logger", "logs").logger("logger");

var privKey = fs.readFileSync(
  path.resolve(__dirname, "./keys/maybank-private.pem"),
  { encoding: "utf8", flag: "r" }
);

var pubKey = fs.readFileSync(
  path.resolve(__dirname, "./keys/visa-public.pem"),
  { encoding: "utf8", flag: "r" }
);

const decryptData = async (body) => {
  const encryptedPayloadString = body;
  let encryptedPayload =
    typeof encryptedPayloadString == "string"
      ? JSON.parse(encryptedPayloadString)
      : encryptedPayloadString;
  let keystore = nodeJose.JWK.createKeyStore();
  let decProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };
  let decryptionKey = privKey;
  return keystore.add(decryptionKey, "pem", decProps).then((key) => {
    return nodeJose.JWE.createDecrypt(key)
      .decrypt(encryptedPayload.Input)
      .then((result) => {
        console.log(Buffer.from(result.plaintext, "base64").toString());
        return result;
      });
  });
};

const encryptData = async (body) => {
  const payload = body.Input;
  let payloadString =
    typeof payload === "string" ? payload : JSON.stringify(payload);
  let keystore = nodeJose.JWK.createKeyStore();
  const iat = Date.now();
  let encProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };
  let encryptionCert = pubKey;
  return keystore
    .add(encryptionCert, "pem", encProps)
    .then((key) => {
      return nodeJose.JWE.createEncrypt(
        {
          format: "compact",
          fields: {
            enc: "A128GCM",
            iat: iat,
          },
        },
        key
      )
        .update(payloadString)
        .final()
        .then((result) => {
          logger.info({
            app: "visa",
            path: "visa/controller/encryptData",
            msg: "Encrypt data successfull",
            result: {
              JWEHeader: {
                alg: "RSA-OAEP-256",
                enc: "A128GCM",
                iat: iat,
                kid: body.JWEHeader.kid,
              },
              Output: result,
            },
          });
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
    .catch((err) => {
      logger.error({
        app: "visa",
        path: "visa/controller/encryptData",
        msg: "Failed to Encrypt Data",
        payload: {
          encryptedData: body.Input,
        },
      });
      return { error: err };
    });
};

app.use(bodyParser.json());

app.post("/api/v1/encrypt", async (req, res) => {
  const encryptedData = await encryptData(req.body);
  res.send(encryptedData);
});

app.post("/api/v1/decrypt", async (req, res) => {
  const decryptedData = await decryptData(req.body);
  res.send(decryptedData);
});

// start the server
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
// console.log(Server is listening on port ${PORT});
// });

// Node.js modules
const fs = require("fs");
const nodeJose = require("node-jose");
const path = require("path");

// Logger module
const Logger = require("./logger");
// const logger = new Logger('logger', 'logs').logger('logger');

// Encryption function
const privKey = fs.readFileSync(
  path.resolve(__dirname, "./keys/maybank-private.pem"),
  { encoding: "utf8", flag: "r" }
);

async function encryptData(body) {
  const payload = body.Input;
  let payloadString =
    typeof payload === "string" ? payload : JSON.stringify(payload);
  let keystore = nodeJose.JWK.createKeyStore();
  const iat = Date.now();
  let encProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };
  let encryptionCert = fs.readFileSync(
    path.resolve(__dirname, "./keys/visa-public.pem"),
    { encoding: "utf8", flag: "r" }
  );

  return keystore
    .add(encryptionCert, "pem", encProps)
    .then((key) => {
      return nodeJose.JWE.createEncrypt(
        {
          format: "compact",
          fields: {
            enc: "A128GCM",
            iat: iat,
          },
        },
        key
      )
        .update(payloadString)
        .final()
        .then((result) => {
          logger.info({
            app: "visa",
            path: "visa/controller/encryptData",
            msg: "Encrypt data successful",
            result: {
              JWEHeader: {
                alg: "RSA-OAEP-256",
                enc: "A128GCM",
                iat: iat,
                kid: body.JWEHeader.kid,
              },
              Output: result,
            },
          });
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
    .catch((err) => {
      logger.error({
        app: "visa",
        path: "visa/controller/encryptData",
        msg: "Failed to encrypt data",
        payload: {
          encryptedData: body.Input,
        },
      });
      return { error: err };
    });
}

// Decryption function
async function decryptData(body) {
  const encryptedPayloadString = body;
  let encryptedPayload =
    typeof encryptedPayloadString == "string"
      ? JSON.parse(encryptedPayloadString)
      : encryptedPayloadString;
  let keystore = nodeJose.JWK.createKeyStore();
  let decProps = {
    kid: body.JWEHeader.kid,
    alg: "RSA-OAEP-256",
    enc: "A128GCM",
  };
  let decryptionKey = privKey;
  return keystore.add(decryptionKey, "pem", decProps).then((key) => {
    return nodeJose.JWE.createDecrypt(key)
      .decrypt(encryptedPayload.Input)
      .then((result) => {
        console.log(Buffer.from(result.plaintext, "base64").toString());
        return result;
      });
  });
}
