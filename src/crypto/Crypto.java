package crypto;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;

import Util.NonceTimestampTuple;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;

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
	public static KeyPair generateKeyPair() {
		KeyPairGenerator generator = new KeyPairGenerator();
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
			generator.initialize(256, sr);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.err.println("Could not create secure random generator");
			e.printStackTrace();
			System.exit(1);
		}
		return generator.generateKeyPair();
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
	 * @param privKey
	 * @param jsonCanonicalized
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(PrivateKey privKey, String jsonCanonicalized) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        signature.initSign(privKey);
        // not sure about this first empty run, took it from:
        // https://github.com/str4d/ed25519-java/blob/master/test/net/i2p/crypto/eddsa/EdDSAEngineTest.java
        signature.update(new byte[] {0});
        signature.sign();
        signature.update(jsonCanonicalized.getBytes());       
        return signature.sign();
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
	public static boolean validateSignature(PublicKey publicKey, String json, byte[] signatureBA, NonceTimestampTuple nonce) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		Signature sign = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
		sign.initVerify(publicKey);
		sign.update(json.getBytes());
		if(!NonceRegistry.checkNonce(nonce, lifetime+1)) {
			throw new SecurityException("nonce reuse detected");
		}
		return sign.verify(signatureBA);
	}
}
