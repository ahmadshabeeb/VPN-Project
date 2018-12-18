import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.OutputStream;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private SessionIV sessionIV;
    private Cipher cipher;

    public SessionEncrypter(SessionKey sessionKey, SessionIV sessionIV) throws Exception{
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), sessionIV.getSessionIvSpec());
        return new CipherOutputStream(output,cipher);
    }
}
