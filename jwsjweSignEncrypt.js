/*
Date: 26-06-2021
*/
var util = require('util');
var crypto = require('crypto');
var jose = require('jose');
let ctx = session.name('api') || session.createContext('api');

function jwsSignEncRSv1(signParam, signkey, signerrcode, encalg, hdrkeyenc, encpubkey, serialize, encerrorcode) {

    try {
				    let repyld = JSON.stringify(signParam);
					var buffer1 = new Buffer(repyld);
                    var buffer = Buffer.from(buffer1);
        var jwsHdrsign = jose.createJWSHeader(signkey, "RS256");
        jose.createJWSSigner(jwsHdrsign).update(buffer).sign('compact', function(error, jwsObj) {
            if (error) {
                console.error("Signature Generation Failed:" + error);
                session.reject(signerrcode);
            } else {
                    console.log("signout: " + jwsObj);			
                    try {
                        var jweHdr = jose.createJWEHeader(encalg);
                        jweHdr.setProtected('alg', hdrkeyenc);
						jweHdr.setProtected('cty', 'JWT');
                        jweHdr.setKey(encpubkey);
                        jose.createJWEEncrypter(jweHdr).update(jwsObj).encrypt(serialize, function(error, jweCompactObj) {
                            if (error) {
                                console.error("Generating Encrypted Data Failed:" + error);
								session.reject(encerrorcode);
                                return
                            } else {
                               	session.output.write(jweCompactObj);
								console.log("Encrypted Data:" + jweCompactObj);
                            }
                        });

                    } catch (e) {
                        console.error("Generating Encrypted Data Failed:" + error);
                        session.reject(encerrorcode);
                    }
            }
        })



    } catch (e) {
        console.error("Signature Generation Failed:" + e);
        session.reject(signerrcode);
    }
}
module.exports.jwsSignEncRSv1 = jwsSignEncRSv1;