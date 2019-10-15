package crypto;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Util.NonceTimestampTuple;

public class Crypto {
	/**
	 * How long in seconds a signature is valid.
	 * The nonce cannot be reused for lifetime + 1s 
	 */
	public static final int lifetime = 60;
	/**
	 * Generates a public/private EdDSA key pair
	 * @return
	 */
	
	public static KeyEd25519Pair generateKeyPair() {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom RANDOM = new SecureRandom();
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        return new KeyEd25519Pair(publicKey, privateKey);
	}
	
	/**
	 * Generates a random string of a specified length for the allowed chars passed
	 * @param length
	 * @return
	 */
	public static String createRandomString(int length, ArrayList<String> allowedChars) {
		String session = "";
		try {
			SecureRandom secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
			int[] ints = secureRandomGenerator.ints(length, 0, allowedChars.size()).toArray();
			for (int i = 0; i < ints.length; i++) {		
				session += allowedChars.get(ints[i]); 
			}

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.err.println("Error creating secure random string");
			e.printStackTrace();
		}
		return session;
	}
	
	/**
	 * Creates a ED_25519 signature for jsonCanonicalized with the private key
	 * @param privateKey
	 * @param jsonCanonicalized
	 * @return
	 * @throws CryptoException 
	 * @throws DataLengthException 
	 * @throws Exception
	 */
	public static byte[] sign(Ed25519PrivateKeyParameters privateKey, String jsonCanonicalized) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, DataLengthException, CryptoException {
		byte[] message = jsonCanonicalized.getBytes();
        Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();
        return signature;
	}
	
	/**
	 * Verifies the ED_25519 signature of signatureBA matches json with the provided public key
	 * Furthermore the nonce is checked for validity. 
	 * @param publicKey
	 * @param json
	 * @param signatureBA
	 * @param nonce
	 * @return
	 * @throws Exception
	 */
	public static boolean validateSignature(Ed25519PublicKeyParameters publicKey, String json, byte[] signatureBA, NonceTimestampTuple nonce) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] message = json.getBytes();

        Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        boolean verifyRes = verifier.verifySignature(signatureBA);
		
		if(!NonceRegistry.checkNonce(nonce, lifetime+1)) {
			throw new SecurityException("nonce reuse detected");
		}
		return verifyRes;
	}
}
