package demo;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import Util.NonceTimestampTuple;
import Util.StringUtils;
import crypto.Crypto;

public class HTTPSignatureDemo {
	public static void main(String[] args) throws Exception {
		
		// Note: lib/ed25519.jar was compiled from the code base of https://github.com/str4d/ed25519-java on the 20.08.19
		
		KeyPair kp = Crypto.generateKeyPair();
		PublicKey pubKey = kp.getPublic();
		PrivateKey privKey = kp.getPrivate();	
	    
		// 1 - Create a JSON (requestJSON) describing the request we wish to sign including a nonce
		long timestamp = System.currentTimeMillis() / 1000L; // UNIX Epoch (long - 64 bit)
		String nonce = Crypto.createRandomString(16,StringUtils.getAllowedSessionChars());
		String body = "some body"; 
		String method = "PUT";
		String uri = "my.url.ch/resources/17";
		String toSignJSON = StringUtils.getToSignJSON(nonce,timestamp, uri, method, body);
		
		// 2 - Canonized requestJSON (requestJSONCanonized)
		String toSignJSONCanonicalized = StringUtils.canonicalizeJSON(toSignJSON);
		
		// 3 - Sign requestJSONCanonized and encode it base 64 (signedRequest)
		byte[] clientSignature = Crypto.sign(privKey, toSignJSONCanonicalized);
		String clientSignatureB64 = Base64.getEncoder().encodeToString(clientSignature);
		
		// 4 - Create the JSON (signatureJSON) that holds the signature, nonce and timestamp, then encode it base 64
		String clientSignatureAndMetaDataJSON = StringUtils.getSignatureJSON(nonce, timestamp, clientSignatureB64);
		String clientSignatureAndMetaDataJSONB64 = Base64.getEncoder().encodeToString(clientSignatureAndMetaDataJSON.getBytes());
		
		// 5 - Create the X-HTTP-Signature Header which will be sent along the request (header)
		String clientSignatureHeader = "X-HTTP-SIGNATURE: "+clientSignatureAndMetaDataJSONB64;
		
		// -- Server Side --
		// Here we re-use the values defined above
		// In "real" code those values have to be taken from the actual request 
		// as received by the server.
		String xHttpSignatureValue = clientSignatureAndMetaDataJSON;
		String requestURI = uri;
		String requestMethod = method;
		String requestBody = body;
		
		// 6 - Reconstruct requestJSON on the server (requestJSONServer) using the request information (method, uri, body)
		//     and the nonce & signature form signatureJSON. 
        String serverCreatedClientJSON = StringUtils.createJSONForSignatureCheck(xHttpSignatureValue, requestURI, requestMethod, requestBody);
        
        // 7 - Validate the signature and requestJSONServer using the public key of the client
        byte[] clientSignatureFromHeader = StringUtils.getSignatureBA(clientSignatureAndMetaDataJSON);
        NonceTimestampTuple signatureNonce = StringUtils.getNonceTuple(serverCreatedClientJSON);
        boolean success = Crypto.validateSignature(pubKey, serverCreatedClientJSON, clientSignatureFromHeader, signatureNonce);
        
        // 8 - Validating the same signature again should throw an exception due to the nonce being reused within the validity/lifetime of the signature
        boolean nonceReplayWorks = true;
        try {
        	Crypto.validateSignature(pubKey, serverCreatedClientJSON, clientSignatureFromHeader, signatureNonce);
        }catch (SecurityException e) {
        	nonceReplayWorks=false;
		}
        
        
        // Output
	    StringUtils.sysOutWithAsterisk("1 - requestJSON");
		System.out.println(toSignJSON);
		System.out.println("\r\n");
		
	    StringUtils.sysOutWithAsterisk("2 - requestJSONCanonized");
		System.out.println(toSignJSONCanonicalized);
		System.out.println("\r\n");
		
		StringUtils.sysOutWithAsterisk("3 - signedRequest");
        System.out.println(clientSignatureB64);
		System.out.println("\r\n");
        
		StringUtils.sysOutWithAsterisk("4 - signatureJSON");
        System.out.println(clientSignatureAndMetaDataJSON);
		System.out.println("\r\n");
        
		StringUtils.sysOutWithAsterisk("5 - header");
        System.out.println(clientSignatureHeader);
		System.out.println("\r\n");
		
		System.out.println("***** CONTEXT CHANGE - SERVER SIDE *****\r\n\r\n");
		
		StringUtils.sysOutWithAsterisk("6 - requestJSONServer");
        System.out.println(serverCreatedClientJSON);
		System.out.println("\r\n");
		
		StringUtils.sysOutWithAsterisk("7 - * Signature validation *");
        System.out.println("Valid? "+success);
		System.out.println("\r\n");

		StringUtils.sysOutWithAsterisk("8 - * Replay nonce check *");
        System.out.println("Nonce replay works? "+nonceReplayWorks);
		System.out.println("\r\n");

	}

	
}
