package Util;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Set;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import crypto.Crypto;

public class StringUtils {
	
	private static JsonParser gson = new JsonParser();
	
	public static byte[] getSignatureBA(String signatureString) {
		JsonObject signatureJO = gson.parse(signatureString).getAsJsonObject();
		String signature = signatureJO.get("signature").getAsString();
		return Base64.getDecoder().decode(signature);
	}
	
	public static NonceTimestampTuple getNonceTuple(String signatureString) {
		JsonObject signatureJO = gson.parse(signatureString).getAsJsonObject();
		return new NonceTimestampTuple(signatureJO.get("__timestamp__").getAsLong(),signatureJO.get("__nonce__").getAsString());
	}
	
	public static String createJSONForSignatureCheck(String signatureString, String uri, String method, String body) throws Exception {
		JsonObject signatureJO = gson.parse(signatureString).getAsJsonObject();
		String nonce = signatureJO.get("__nonce__").getAsString();
		long timestamp = signatureJO.get("__timestamp__").getAsLong();

		long currentTimestamp =  System.currentTimeMillis() / 1000L;
		if(timestamp+Crypto.lifetime<currentTimestamp) {
			throw new SecurityException("Signature Check failed - Timestamp older than "+Crypto.lifetime+ " seconds");
		}
		String bodyJ="";
		if(body!=null) {
			bodyJ = ",\"body\":\""+Base64.getEncoder().encodeToString(body.getBytes())+"\"";
		}
		String json = "{\"__nonce__\":\""+nonce+"\",\"__timestamp__\":"+timestamp+bodyJ+",\"method\":\""+method+"\",\"uri\":\""+uri+"\"}";
		return json;
	}
	
	public static String getSignatureJSON(String nonce, long timestamp, String signature) {		
		String signatureJSON="{\n" + 
				"    \"__nonce__\": \""+nonce+"\",\n" + 
				"    \"__timestamp__\": "+timestamp+",\n" + 
				"    \"signature\": \""+signature+"\"\n" + 
				"}";
		return signatureJSON;
	}
	
	public static String getToSignJSON(String nonce, long timestamp, String uri, String method) {		
		String toSignJSON="{\n" + 
				"    \"__nonce__\": \""+nonce+"\",\n" + 
				"    \"__timestamp__\": "+timestamp+",\n" + 
				"    \"uri\": \""+uri+"\",\n" + 
				"    \"method\": \""+method+"\"\n" + 
				"}";
		return toSignJSON;
	}
	
	public static String getToSignJSON(String nonce, long timestamp, String uri, String method, String body) {
		String bodyB64 = Base64.getEncoder().encodeToString(body.getBytes());
		
		String toSignJSON="{\n" + 
				"    \"__nonce__\": \""+nonce+"\",\n" + 
				"    \"__timestamp__\": "+timestamp+",\n" + 
				"    \"uri\": \""+uri+"\",\n" + 
				"    \"method\": \""+method+"\",\n" + 
				"    \"body\": \""+bodyB64+"\"\n" + 
				"}";
		return toSignJSON;
	}
	
	/**
	 * Canonicalizes JSON String, no whitespaces, ascii value sorted, one line
	 * @param json
	 * @return
	 */
	public static String canonicalizeJSON(String json) {
		JsonObject jo = gson.parse(json).getAsJsonObject();
		Set<String> keys = jo.keySet();
		
		ArrayList<String> keysAL = new ArrayList<String>(keys);
		keysAL.sort(new ASCIIValueSorter());
		String jsonRes="{";
		for (int i = 0; i < keysAL.size(); i++) {
			String key = keysAL.get(i);
			if(jo.get(key).getAsJsonPrimitive().isString()) {
				jsonRes+="\""+key+"\":\""+jo.get(key).getAsString()+"\"";		
			}else {
				jsonRes+="\""+key+"\":"+jo.get(key).getAsLong();
			}
			if(i<keysAL.size()-1) {
				jsonRes+=",";
			}
		}
		jsonRes+="}";
		return jsonRes;
	}
	
	public static void sysOutWithAsterisk(String strng) {
		String asterisk="";
		for (int i = 0; i < strng.length(); i++) {
			asterisk+="*";
		}
		System.out.println(strng+"\r\n"+asterisk);
	}
	
	
	private static final ArrayList<String> allowedChars = new ArrayList<String>();
	
	public static ArrayList<String> getAllowedSessionChars() {
		if(allowedChars.size()==0) {
			allowedChars.addAll(getASCIICharacters(48, 57));  // 0-9
			allowedChars.addAll(getASCIICharacters(65, 90));  // A-Z
			allowedChars.addAll(getASCIICharacters(97, 122)); // a-z
		}
		return allowedChars;
	}
	
	private static ArrayList<String> getASCIICharacters(int from, int to){
		ArrayList<String> chars = new ArrayList<String>();
		for (int i = from; i <= to; i++) {
			chars.add(String.valueOf((char)i));
		}
		return chars;
	}
}
