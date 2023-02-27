var hm = require('header-metadata');                            // GatewayScript header-metadata module provides methods to access the protocol headers in requests or responses
var service = require('service-metadata');                      // service-metadata module supports accessing service variables
var fs = require('fs');                                         // Node.js file system module let you work with the file system on your computer. Common use: Read files, Create files, Update files, Delete files, Rename files
var url = require('url');                                       // Node.js URL module splits up a web address into readable parts
var querystring = require('querystring');                       // Node.js querystring module provides utilities for parsing and formatting URL query strings
var ct = session.name('api') || session.createContext('api');   // GatewayScript session object supports a transaction flow in a GatewayScript application to access input, output, and other contexts that are visible to the service
// https://github.com/ibm-datapower/datapower-playground/blob/master/src/web/public/doc/api/context.markdown
let properties = hm.current.get('X-MB-lk'); 
ct.setVar('X-MB-lk', hm.current.get('X-MB-lk'));                // set/get/delete variable on the named context 
ct.setVar('X-MB-srvcind', hm.current.get('X-MB-srvcind'));      
var urlopen = require('urlopen');                               // urlopen module provides APIs to establish a non-streaming connection with target servers by HTTP, HTTPS, Kafka, or IBM® MQ protocol and open files in the DataPower file system
var jose = require('jose');                                     //jose module provides APIs to encrypt and decrypt messages and to sign and verify messages. Encryption and decryption use JSON Web Encryption (JWE) specifications. Signing and verifying messages use JSON Web Signature (JWS) specifications
var jwsjwesign = require('local:/api2/common/security/VisaEncrypt.js');

try {
    // Read the lookup file as JSON 
    // properties is the file to read
    // callback function (function passed as an argument to another function) contains error and data. Since we cannot use try/catch in asynchronous code, this function will return error object is something goes wrong. It is null if no errors
    fs.readAsJSON(properties, function (error, cf) {
        if (error) {                                        // Check if there is error in request
            console.error("Req Error:" + error);
            session.reject('ARQ800');
        } else {                                            // No error in request
            var sourceid = hm.current.get('sourceid');      
            var tid = hm.current.get('transactionid');
            var tmstamp = hm.current.get('X-MB-Timestamp');
            var gtid = hm.current.get('X-MB-E2E-Id');
            
            // Request Header Log
            console.log("Info:: Incoming-ReqHdr -> " + "sourceid: " + sourceid + "; tid: " + tid + "; timestamp: " + tmstamp);
            if (sourceid !== undefined) {
                ct.setVar("sourceid", sourceid);
            }
            if (tid !== undefined) {
                ct.setVar("transactionid", tid);
            }
                
            let i = hm.current.get('X-MB-srvcind');
            let userCred = cf.ServiceDetails[i].EncryptionInfo.userCred;    // Get userCred from lookup (EncryptionInfo)
            let passCred = cf.ServiceDetails[i].EncryptionInfo.passCred;    // Get passCred from lookup (EncryptionInfo)
            
            // Buffer allows handling streams of binary data
            // Here, buffer is used to take a string or piece of data and doing base64 encoding
            // https://pthree.org/2011/04/06/convert-text-to-base-64-by-hand/
            var authzB64 = Buffer.from(userCred + ':' + passCred).toString('base64');
            var authzHdr = 'Basic ' + authzB64;
            var timestamp = Math.round(new Date().getTime()/1000);
            var kid = cf.ServiceDetails[i].EncryptionInfo.kid;              // Get kid from lookup (EncryptionInfo)
            ct.setVar("kid", kid);
            var clientcert = cf.ServiceDetails[i].EncryptionInfo.ClientCert;// Get clientcert from lookup (EncryptionInfo)
            ct.setVar("clientcert", clientcert);
            session.parameters.encAlg = "A128GCM";                          // JWE Encryption Algorithm
            session.parameters.keyMgmtAlg = "RSA-OAEP-256";                 // JWE Key Management Algorithm
            session.parameters.outputFormat = "compact";

            var decKey = cf.ServiceDetails[i].DecrptionInfo.decKey;         // Get deckey from lookup (DecrptionInfo)
            ct.setVar("decKey", decKey);
            
            
            
            //Decryption-Encryption-Endpoint
            var encEp = cf.ServiceDetails[i].EncryptionInfo.encryptUrl;     // Get encryptUrl from lookup (EncryptionInfo)
            var encdecSslfPrf = cf.ServiceDetails[i].EncryptionInfo.sslPrf; // Get sslPrf from lookup (EncryptionInfo)
            ct.setVar("encdecSslfPrf", encdecSslfPrf);      
            
            // Session input refers to the context body information
            // Read the body as JSON 
            session.input.readAsJSON(function (errJson, msg) {
                if (errJson) {
                    console.error("Error:: Invalid message type. " + errJson);
                    session.reject('ARQ401');
                } else {
                    console.log("Info:: Incoming-ReqData -> " + JSON.stringify(msg));   // Logging the request data, convert json object into string (exact same words will be printed)
                    
                    let Mbbkey = cf.ServiceDetails[i].SignatureInfo.Mbbkey;
                    let signerrcode = 'ARS406';
                    let encalg = cf.ServiceDetails[i].EncryptionInfo.EncAlg;                // A128GCM
                    let hdrkeyenc = cf.ServiceDetails[i].EncryptionInfo.HdrKeyEnc;          // RSA-OAEP-256
                    let ClientEncCert = cf.ServiceDetails[i].EncryptionInfo.ClientCert;     // Visa_EncCer
                    let serialize = cf.ServiceDetails[i].EncryptionInfo.Serialize;                      
                    let encerrorcode = 'ARS410'

                    var iat = Date.now();
                    var jwsparms = {
                        "iat": iat
                    };
                    var replyID = JSON.stringify(jwsparms);
                    var buffer1 = new Buffer(replyID);
                    var buffer = Buffer.from(buffer1);
                    var jwsHdrsign = jose.createJWSHeader(Mbbkey, "RS256");
                    jwsHdrsign.setProtected('typ', 'JWT');
                    jose.createJWSSigner(jwsHdrsign).update(buffer).sign('compact', function (error, jwsObj) {
                        if (error) {
                            console.error("Signature Generation Failed:" + error);
                            session.reject('ARQ411');
                        } else {
                            try {
                                var jweHdr = jose.createJWEHeader(encalg);
                                var iat = Date.now();
                                jweHdr.setProtected({
                                    "alg": hdrkeyenc,
                                    "cty": "application/json;charset=UTF-8"
                                });
                                console.log("HERE IS HEADER IAT " + JSON.stringify(jweHdr.getProtected('iat')));
                                jweHdr.setKey(ClientEncCert);
                                jose.createJWEEncrypter(jweHdr).update(JSON.stringify(msg), 'utf8').encrypt(serialize, function (error, jweCompactObj) {
                                    if (error) {
                                    console.error("Generating Encrypted Data Failed:" + error);
                                    session.reject(encerrorcode);
                                    } else {
                                    // Wrap the JWE compact object in a JSON object with the property "encData"
                                    var result = {
                                        encData: jweCompactObj,
                                    };
                                    // Convert the result object to a JSON string
                                    var jsonString = JSON.stringify(result);
                                    // Write the JSON string to the session output
                                    session.output.write(result); // output as JSON string
                                    console.log("Latest Encrypted Data:" + jsonString);
                                    }
                                });
                            } catch (e) {
                                console.error("Generating Encrypted Data Failed:" + e);
                                session.reject(encerrorcode);
                            }
                        }
                    });

                    // Request Header to Provider
                    hm.current.set('Accept', 'application/json');                   
                    hm.current.set('Authorization', authzHdr);
                    hm.current.set('keyId', kid);                   
                    console.log("Info:: Outgoing-ReqHdr -> " + "Authorization:xxx;kid:" + kid);
                    
                }
            });
        }
    });
} catch (e) {
    console.error("Error:: Gateway unknown error, " + e);
    session.reject('ARQ102');
}

var encryptData = async function(dataToEncrypt) {
    return new Promise(function (resolve, reject) {
        var jweHdr = jose.createJWEHeader(session.parameters.encAlg);
        jweHdr.setProtected('alg', session.parameters.keyMgmtAlg);
        jweHdr.setKey("Visa_EncCer");

        jose.createJWEEncrypter(jweHdr).update(dataToEncrypt, 'utf8').encrypt(outputFormat, function(error, encrypted) {
            if (error) {
                console.error("Error:: Error encrypt message. " + error);
                session.reject('ARQ410');
            } else {
                console.log("HERE: " + dataToEncrypt);
                console.log("HERE: " + encrypted);
                resolve(encrypted);
            }
        });
    });
}
