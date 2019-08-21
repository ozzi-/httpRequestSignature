package Util;

public class NonceTimestampTuple {
	private long timestamp;
	private String nonce;

	// nonce obj is equals when the nonce itself matches, timestamp does not matter here 
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof NonceTimestampTuple) {
			NonceTimestampTuple other = (NonceTimestampTuple) obj;
			return (this.getNonce().equals(other.getNonce()));
		}
		return false;
	}
	
	@Override
	public int hashCode() {
        int result = 17;
        result = 31 * result + nonce.hashCode();
        return result;
	}

	public NonceTimestampTuple(long timestamp, String nonce) {
		this.setTimestamp(timestamp);
		this.setNonce(nonce);
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
}
