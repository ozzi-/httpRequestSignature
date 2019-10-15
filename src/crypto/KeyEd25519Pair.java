package crypto;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

public class KeyEd25519Pair{
	
	private Ed25519PrivateKeyParameters privateKey;
	private Ed25519PublicKeyParameters publicKey;
	
	public KeyEd25519Pair(Ed25519PublicKeyParameters publicKey, Ed25519PrivateKeyParameters privateKey) {
		this.setPrivateKey(privateKey);
		this.setPublicKey(publicKey);
	}

	public Ed25519PrivateKeyParameters getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(Ed25519PrivateKeyParameters privateKey) {
		this.privateKey = privateKey;
	}

	public Ed25519PublicKeyParameters getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(Ed25519PublicKeyParameters publicKey) {
		this.publicKey = publicKey;
	}
	
}
