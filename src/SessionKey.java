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

    public SessionKey (String encodedKey) {
        decodeKey(encodedKey);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    private void decodeKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
