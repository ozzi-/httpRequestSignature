package demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import Util.NonceTimestampTuple;
import Util.StringUtils;
import crypto.Crypto;
import crypto.KeyEd25519Pair;

public class HTTPSignatureDemo {
	

	public static void main(String[] args) throws Exception {
		
		KeyEd25519Pair keyPair = Crypto.generateKeyPair();
		Ed25519PrivateKeyParameters privateKey = keyPair.getPrivateKey();
		Ed25519PublicKeyParameters publicKey = keyPair.getPublicKey();
		
		// 1 - Create a JSON (requestJSON) describing the request we wish to sign
		// including a nonce
		long timestamp = System.currentTimeMillis() / 1000L; // UNIX Epoch (long - 64 bit)
		String nonce = Crypto.createRandomString(16, StringUtils.getAllowedSessionChars());
		String body = "some body";
		String method = "PUT";
		String uri = "http://some.url.ch";
		String toSignJSON = StringUtils.getToSignJSON(nonce, timestamp, uri, method, body);

		// 2 - Canonized requestJSON (requestJSONCanonized)
		String toSignJSONCanonicalized = StringUtils.canonicalizeJSON(toSignJSON);

		// 3 - Sign requestJSONCanonized and encode it base 64 (signedRequest)
		byte[] clientSignature = Crypto.sign(privateKey, toSignJSONCanonicalized);
		String clientSignatureB64 = Base64.getEncoder().encodeToString(clientSignature);

		// 4 - Create the JSON (signatureJSON) that holds the signature, nonce and
		// timestamp, canonicalize it, then encode it base 64
		String clientSignatureAndMetaDataJSON = StringUtils.canonicalizeJSON(StringUtils.getSignatureJSON(nonce, timestamp, clientSignatureB64));
		String clientSignatureAndMetaDataJSONB64 = Base64.getEncoder().encodeToString(clientSignatureAndMetaDataJSON.getBytes());

		// 5 - Create the X-HTTP-Signature Header which will be sent along the request
		// (header)
		String clientSignatureHeader = "X-HTTP-SIGNATURE: " + clientSignatureAndMetaDataJSONB64;

		// -- Server Side --
		// Here we re-use the values defined above
		// In "real" code those values have to be taken from the actual request
		// as received by the server.
		String xHttpSignatureValue = clientSignatureAndMetaDataJSON;
		String requestURI = uri;
		String requestMethod = method;
		String requestBody = body;

		// 6 - Reconstruct requestJSON on the server (requestJSONServer) using the
		// request information (method, uri, body)
		// and the nonce & signature form signatureJSON.
		String serverCreatedClientJSON = StringUtils.createJSONForSignatureCheck(xHttpSignatureValue, requestURI,
				requestMethod, requestBody);

		// 7 - Validate the signature and requestJSONServer using the public key of the
		// client
		byte[] clientSignatureFromHeader = StringUtils.getSignatureBA(clientSignatureAndMetaDataJSON);
		NonceTimestampTuple signatureNonce = StringUtils.getNonceTuple(serverCreatedClientJSON);
		
		boolean success = Crypto.validateSignature(publicKey, serverCreatedClientJSON, clientSignatureFromHeader,
				signatureNonce);

		// 8 - Validating the same signature again should throw an exception due to the
		// nonce being reused within the validity/lifetime of the signature
		boolean nonceReplayWorks = true;
		try {
			Crypto.validateSignature(publicKey, serverCreatedClientJSON, clientSignatureFromHeader, signatureNonce);
		} catch (SecurityException e) {
			nonceReplayWorks = false;
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
		System.out.println("Valid? " + success);
		System.out.println("\r\n");

		StringUtils.sysOutWithAsterisk("8 - * Replay nonce check *");
		System.out.println("Nonce replay works? " + nonceReplayWorks);
		System.out.println("\r\n");
		

		String publicKeyB64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

		testSignature("http://test.ch/api/v1/signatureCheck", body, publicKeyB64, clientSignatureAndMetaDataJSONB64, uri, method, String.valueOf(timestamp));
		
	}


	private static void testSignature(String destURL, String body, String headerPublicKey, String headerSignature, String headerUri,
			String headerMethod, String headerTime) {

//		Example code for backend
//      ************************
//		Base64.Decoder decoder = Base64.getDecoder();
//		
//		String body =  StringUtils.getToSignJSON(nonce, timestampInMilliseconds, uri, method, message);
//		String bodyCanonicalized = StringUtils.canonicalizeJSON(body);
//		
//		byte [] messageBA = bodyCanonicalized.getBytes();
//		byte [] signatureBA = decoder.decode(signature);
//		byte [] publicKeyBA = decoder.decode(public_signing_key);
//		
//		Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(publicKeyBA, 0);
//		
//		Signer verifier = new Ed25519Signer();
//		verifier.init(false, publicKey);
//		verifier.update(messageBA, 0, messageBA.length);
//		return verifier.verifySignature(signatureBA);
	
		
		try {
			URL url = new URL(destURL);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "text/plain");
			conn.setRequestProperty("X-PUBLIC-KEY", headerPublicKey);
			conn.setRequestProperty("X-HTTP-SIGNATURE", headerSignature);
			conn.setRequestProperty("uri", headerUri);
			conn.setRequestProperty("method", headerMethod);
			conn.setRequestProperty("current-time", headerTime);
			
			OutputStream os = conn.getOutputStream();
			os.write(body.getBytes());
			os.flush();

			BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

			String output;
			System.out.println("Output from Server .... \n");
			while ((output = br.readLine()) != null) {
				System.out.println(output);
			}

			conn.disconnect();

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
