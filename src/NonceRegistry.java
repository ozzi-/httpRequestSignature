import java.util.HashSet;
import java.util.Iterator;

public class NonceRegistry {
	private static HashSet<NonceTimestampTuple> nonces = new HashSet<NonceTimestampTuple>();
	
	/**
	 * Returns true if the nonce has not been seen in the specified lifetime
	 * Returns false if the nonce has been already used in the specified lifetime
	 * @param nonce
	 * @param lifetime
	 * @return
	 */
	public static boolean checkNonce(NonceTimestampTuple nonce, int lifetime) {
		// check for old nonces in registry
		long currentTimestamp = System.currentTimeMillis() / 1000L;
		Iterator<NonceTimestampTuple> noncesIterator = nonces.iterator();
		while (noncesIterator.hasNext()) {
			NonceTimestampTuple nonceC = noncesIterator.next();
			if(nonceC.getTimestamp()+lifetime < currentTimestamp) {
				noncesIterator.remove();
			}
		}
		
		boolean nonceOK = false;
		if(!nonces.contains(nonce)) {
			nonces.add(nonce);
			nonceOK = true;
		}
        
        return nonceOK;
	}
}
