var util = require("util");
var crypto = require("crypto");
var jose = require("jose");
let ctx = session.name("api") || session.createContext("api");

function jwsSignEncRSv1(
  signParam,
  signkey,
  signerrcode,
  encalg,
  hdrkeyenc,
  encpubkey,
  serialize,
  encerrorcode
) {
  try {
    // Convert the signParam object to a JSON string
    let repyld = JSON.stringify(signParam);
    var buffer1 = new Buffer(repyld);
    var buffer = Buffer.from(buffer1);

    // Create the JWS header with the signkey and algorithm (RS256)
    var jwsHdrsign = jose.createJWSHeader(signkey, "RS256");

    // Sign the payload buffer with the JWS header
    jose
      .createJWSSigner(jwsHdrsign)
      .update(buffer)
      .sign("compact", function (error, jwsObj) {
        if (error) {
          console.error("Signature Generation Failed:" + error);
          session.reject(signerrcode);
        } else {
          console.log("signout: " + jwsObj);
          try {
            // Create the JWE header with the encryption algorithm, key encryption algorithm and content type
            var jweHdr = jose.createJWEHeader(encalg);
            jweHdr.setProtected("alg", hdrkeyenc);
            jweHdr.setProtected("cty", "JWT");
            jweHdr.setKey(encpubkey);

            // Encrypt the JWS object with the JWE header
            jose
              .createJWEEncrypter(jweHdr)
              .update(jwsObj)
              .encrypt(serialize, function (error, jweCompactObj) {
                if (error) {
                  console.error("Generating Encrypted Data Failed:" + error);
                  session.reject(encerrorcode);
                } else {
                  // Wrap the JWE compact object in a JSON object with the property "encryptedData"
                  var result = {
                    encryptedData: jweCompactObj,
                  };
                  // Convert the result object to a JSON string
                  var jsonString = JSON.stringify(result);
                  // Write the JSON string to the session output
                  session.output.write(jsonString); // output as JSON string
                  console.log("Encrypted Data:" + jsonString);
                }
              });
          } catch (e) {
            console.error("Generating Encrypted Data Failed:" + error);
            session.reject(encerrorcode);
          }
        }
      });
  } catch (e) {
    console.error("Signature Generation Failed:" + e);
    session.reject(signerrcode);
  }
}

module.exports.jwsSignEncRSv1 = jwsSignEncRSv1;
