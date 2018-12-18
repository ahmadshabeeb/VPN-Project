import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SessionKey {
    private SecretKey secretKey;

    public SessionKey (int keyLength) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyLength);
        secretKey = keyGen.generateKey();
    }

    public SessionKey (String encodedStringKey) {
        decodeKey(encodedStringKey);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    private void decodeKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        secretKey =  new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
