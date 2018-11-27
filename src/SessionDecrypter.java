import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.util.Base64;

public class SessionDecrypter {
    private SessionKey sessionKey;
    private IvParameterSpec ivSpec;
    private Cipher cipher;

    SessionDecrypter(String key, String iv) throws Exception{
        this.sessionKey = new SessionKey(key);
        this.ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
    }

    CipherInputStream openCipherInputStream (InputStream input) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivSpec);
        return new CipherInputStream(input, cipher);
    }
}
