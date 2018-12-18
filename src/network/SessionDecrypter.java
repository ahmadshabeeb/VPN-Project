package network;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.InputStream;

public class SessionDecrypter {
    private SessionKey sessionKey;
    private SessionIV sessionIV;
    private Cipher cipher;

    public SessionDecrypter(SessionKey sessionKey, SessionIV sessionIV) throws Exception{
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }

    public CipherInputStream openCipherInputStream (InputStream input) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), sessionIV.getSessionIvSpec());
        return new CipherInputStream(input, cipher);
    }
}
