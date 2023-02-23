var hm = require('header-metadata');							// GatewayScript header-metadata module provides methods to access the protocol headers in requests or responses
var service = require('service-metadata');						// service-metadata module supports accessing service variables
var fs = require('fs');											// Node.js file system module let you work with the file system on your computer. Common use: Read files, Create files, Update files, Delete files, Rename files
var url = require('url');										// Node.js URL module splits up a web address into readable parts
var querystring = require('querystring');						// Node.js querystring module provides utilities for parsing and formatting URL query strings
var ct = session.name('api') || session.createContext('api');	// GatewayScript session object supports a transaction flow in a GatewayScript application to access input, output, and other contexts that are visible to the service
// https://github.com/ibm-datapower/datapower-playground/blob/master/src/web/public/doc/api/context.markdown
let properties = hm.current.get('X-MB-lk');	
ct.setVar('X-MB-lk', hm.current.get('X-MB-lk'));				// set/get/delete variable on the named context	
ct.setVar('X-MB-srvcind', hm.current.get('X-MB-srvcind'));		
var urlopen = require('urlopen');								// urlopen module provides APIs to establish a non-streaming connection with target servers by HTTP, HTTPS, Kafka, or IBM® MQ protocol and open files in the DataPower file system
var jose = require('jose'); 									//jose module provides APIs to encrypt and decrypt messages and to sign and verify messages. Encryption and decryption use JSON Web Encryption (JWE) specifications. Signing and verifying messages use JSON Web Signature (JWS) specifications
var jwsjwesign = require('local:/api2/common/security/jwsjweSignEncrypt.js');

try {
	// Read the lookup file as JSON 
	// properties is the file to read
	// callback function (function passed as an argument to another function) contains error and data. Since we cannot use try/catch in asynchronous code, this function will return error object is something goes wrong. It is null if no errors
	fs.readAsJSON(properties, function (error, cf) {
        if (error) {										// Check if there is error in request
            console.error("Req Error:" + error);
            session.reject('ARQ800');
		} else {											// No error in request
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
			let userCred = cf.ServiceDetails[i].EncryptionInfo.userCred;	// Get userCred from lookup (EncryptionInfo)
			let passCred = cf.ServiceDetails[i].EncryptionInfo.passCred;	// Get passCred from lookup (EncryptionInfo)
			
			// Buffer allows handling streams of binary data
			// Here, buffer is used to take a string or piece of data and doing base64 encoding
			// https://pthree.org/2011/04/06/convert-text-to-base-64-by-hand/
			var authzB64 = Buffer.from(userCred + ':' + passCred).toString('base64');
			var authzHdr = 'Basic ' + authzB64;
			var timestamp = Math.round(new Date().getTime()/1000);
			var kid = cf.ServiceDetails[i].EncryptionInfo.kid;				// Get kid from lookup (EncryptionInfo)
			ct.setVar("kid", kid);
			var clientcert = cf.ServiceDetails[i].EncryptionInfo.ClientCert;// Get clientcert from lookup (EncryptionInfo)
			ct.setVar("clientcert", clientcert);
			session.parameters.encAlg = "A128GCM";							// JWE Encryption Algorithm
			session.parameters.keyMgmtAlg = "RSA-OAEP-256";					// JWE Key Management Algorithm
			session.parameters.outputFormat = "compact";

			var decKey = cf.ServiceDetails[i].DecrptionInfo.decKey;			// Get deckey from lookup (DecrptionInfo)
			ct.setVar("decKey", decKey);
			
			
			
			//Decryption-Encryption-Endpoint
			var encEp = cf.ServiceDetails[i].EncryptionInfo.encryptUrl;		// Get encryptUrl from lookup (EncryptionInfo)
			var encdecSslfPrf = cf.ServiceDetails[i].EncryptionInfo.sslPrf; // Get sslPrf from lookup (EncryptionInfo)
			ct.setVar("encdecSslfPrf", encdecSslfPrf);		
			
			// Session input refers to the context body information
			// Read the body as JSON 
			session.input.readAsJSON(function (errJson, msg) {
				if (errJson) {
					console.error("Error:: Invalid message type. " + errJson);
					session.reject('ARQ401');
				} else {
					console.log("Info:: Incoming-ReqData -> " + JSON.stringify(msg));	// Logging the request data, convert json object into string (exact same words will be printed)
					
					let Mbbkey = cf.ServiceDetails[i].SignatureInfo.Mbbkey;
					let signerrcode = 'ARS406';
					let encalg = cf.ServiceDetails[i].EncryptionInfo.EncAlg;
					let hdrkeyenc = cf.ServiceDetails[i].EncryptionInfo.HdrKeyEnc;
					let ClientEncCert = cf.ServiceDetails[i].EncryptionInfo.ClientCert;
					let serialize = cf.ServiceDetails[i].EncryptionInfo.Serialize;                      
					let encerrorcode = 'ARS410';
					ct.setVar("flag", "VISA");

					/* Sign & Encrypt Request Message */
					jwsjwesign.jwsSignEncRSv1(msg, Mbbkey, signerrcode, encalg, hdrkeyenc, ClientEncCert, serialize, encerrorcode);


					// jose.createJWEEncrypter(jweHdr).update("test").encrypt('compact', function(error, jweObj) {
					// 	if (error) {
					// 		console.error("Error:: Error encrypt message. " + error);
					// 		session.reject('ARQ410');
					// 	} else {
					// 		console.log(jweObj);
					// 	}
					// });

					var reqMsg = {
						// Get the 'Output' from response
						// encData: await encryptData(JSON.stringify(msg))
					};

					session.output.write(reqMsg);
					console.log("Info:: Outgoing-ReqData -> " + JSON.stringify(reqMsg));
					// session.output.write(await encryptData(JSON.stringify(msg)));

					// Message to be encrypted and the format used to encrypt
					// var inEncMsg = {
					// 	"JWEHeader": {
					// 		"alg": "RSA-OAEP-256",
					// 		"enc": "A128GCM",
					// 		"kid": kid
					// 	},
					// 	"Input": msg
					// };
					
					// Message to send request to MCM to encrypt
					// Parameters: https://www.ibm.com/docs/en/datapower-gateway/10.0.x?topic=apis-urlopen-module#urlopen.openforcommunicationwithservers
					// var invokeMCM = {
					// 	target: encEp,
					// 	method: 'post',
					// 	headers: {
					// 		'timestamp': timestamp,
					// 		'sourceid': 'APIGW',
					// 		'transactionid': gtid
					// 	},
					// 	contentType: 'application/json',
					// 	timeout: 20,
					// 	sslClientProfile: encdecSslfPrf,
					// 	data: inEncMsg
					// };
					
					// console.log("Info:: Encryption-Request -> " + JSON.stringify(inEncMsg));
					
					// urlopen will configure a user agent to initiate a request for a local service to establish a connection to target server
					// Here send request of encryption, Response will be available in callback 
					// urlopen.open(invokeMCM, function(urlOpenErr, response) {
					// 	if (urlOpenErr) {
					// 		console.error("Error:: Error invoking MCM. " + urlOpenErr);
					// 		session.reject('ARQ410');
					// 	} else {
					// 		// When connection is established, the response from the responding server is read to obtain the data. The data is obtained by using one of the read APIs (readAsBuffer, readAsBuffers, readAsJSON, readAsXML)
					// 		response.readAsBuffer(function(errBuff, buffmsg) {
					// 		 if (errBuff) {
					// 				console.error("Error:: Error read response as Buffer. " + errBuff);
					// 				session.reject('ARQ401');
					// 			} else {
					// 				// Save base64 response in log (Encrypted)
					// 				console.log("Info:: Encryption-Response (base64) -> " + buffmsg.toString('base64'));
					// 				var parseddata = JSON.parse(buffmsg);
					// 				// Save response in JSON format in log (Encrypted)
					// 				console.log("Info:: Encryption-Response -> " + JSON.stringify(parseddata));
					// 				var reqMsg = {
					// 					// Get the 'Output' from response
					// 					encData: parseddata.Output
					// 				};
									
					// 				// Request Header to Provider
					// 				hm.current.set('Accept', 'application/json');					
					// 				hm.current.set('Authorization', authzHdr);
					// 				hm.current.set('keyId', kid);					
					// 				console.log("Info:: Outgoing-ReqHdr -> " + "Authorization:xxx;kid:" + kid);
									
					// 				// Request Data to Provider Log							
					// 				session.output.write(reqMsg);
					// 				console.log("Info:: Outgoing-ReqData -> " + JSON.stringify(reqMsg));
					// 			}
					// 		});
					// 	}
					// });
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