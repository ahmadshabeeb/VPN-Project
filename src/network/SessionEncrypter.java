package network;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private Cipher cipher;
    private byte[] iv;
    private IvParameterSpec ivParameterSpec;

    public SessionEncrypter(Integer KeyLength) throws Exception {
        sessionKey = new SessionKey(KeyLength);

        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom randomSecureRandom = new SecureRandom();
        iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public String encodeKey() {
        return sessionKey.encodeKey();
    }

    public String encodeIV() throws IOException {
        return Base64.getEncoder().encodeToString(iv);
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        return new CipherOutputStream(output,cipher);
    }
}
