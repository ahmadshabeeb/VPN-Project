import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionKey {
    private SecretKey secretKey;

    public SessionKey (int keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = null;

        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

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
        String StringKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return StringKey;
    }

    private void decodeKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
