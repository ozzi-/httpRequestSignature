import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class HTTPSignatureDemo {
	public static void main(String[] args) throws Exception {
		
		KeyPair kp = Crypto.generateKeyPair();
		PublicKey pubKey = kp.getPublic();
		PrivateKey privKey = kp.getPrivate();	
	    
		// Request Data
		long timestamp = System.currentTimeMillis() / 1000L; // UNIX Epoch (long - 64 bit)
		String nonce = Crypto.createRandomString(16,StringUtils.getAllowedSessionChars());
		String body = "some body"; 
		String method = "PUT";
		String uri = "my.url.ch/resources/17";
		
		// -- Client Side --
		String toSignJSON = StringUtils.getToSignJSON(nonce,timestamp, uri, method, body);
		String toSignJSONCanonicalized = StringUtils.canonicalizeJSON(toSignJSON);
		byte[] clientSignature = Crypto.sign(privKey, toSignJSONCanonicalized);
		String clientSignatureB64 = Base64.getEncoder().encodeToString(clientSignature);
		String clientSignatureAndMetaDataJSON = StringUtils.getSignatureJSON(nonce, timestamp, clientSignatureB64);
		String clientSignatureAndMetaDataJSONB64 = Base64.getEncoder().encodeToString(clientSignatureAndMetaDataJSON.getBytes());
		String clientSignatureHeader = "X-HTTP-SIGNATURE: "+clientSignatureAndMetaDataJSONB64; // send this with the request
		// -- Server Side --
        String serverCreatedClientJSON = StringUtils.createJSONForSignatureCheck(clientSignatureAndMetaDataJSON, uri, method, body);
        byte[] clientSignatureFromHeader = StringUtils.getSignatureBA(clientSignatureAndMetaDataJSON);
        NonceTimestampTuple signatureNonce = StringUtils.getNonce(serverCreatedClientJSON);
        boolean success = Crypto.validateSignature(pubKey, serverCreatedClientJSON, clientSignatureFromHeader, signatureNonce);
        boolean nonceReplayWorks = true;
        try {
        	Crypto.validateSignature(pubKey, serverCreatedClientJSON, clientSignatureFromHeader, signatureNonce);
        }catch (SecurityException e) {
        	nonceReplayWorks=false;
		}
        
        
        // Output
        
	    StringUtils.sysOutWithAsterisk("All data used that is required in the signature as canonicalized JSON");
		System.out.println(toSignJSONCanonicalized);
		System.out.println("\r\n");

		StringUtils.sysOutWithAsterisk("Signed JSON (base 64 encoded) ) = Signature");
        System.out.println(clientSignatureB64);
		System.out.println("\r\n");
        
		StringUtils.sysOutWithAsterisk("Signature and metadata as JSON");
        System.out.println(clientSignatureAndMetaDataJSON);
		System.out.println("\r\n");
        
		StringUtils.sysOutWithAsterisk("Signature and metadata base 64 encoded as Header");
        System.out.println(clientSignatureHeader);
		System.out.println("\r\n");
		
		System.out.println("***** CONTEXT CHANGE - SERVER SIDE *****\r\n\r\n");
		StringUtils.sysOutWithAsterisk("Server constructs JSON - this should match what the client created");
        System.out.println(serverCreatedClientJSON);
		System.out.println("\r\n");
		StringUtils.sysOutWithAsterisk("Signature valid? "+success);
		StringUtils.sysOutWithAsterisk("Nonce replay works? "+nonceReplayWorks);

	}

	
}
