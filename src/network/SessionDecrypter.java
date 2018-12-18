package network;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;

public class SessionDecrypter {
    private SessionKey sessionKey;
    private IvParameterSpec ivSpec;
    private Cipher cipher;

    public SessionDecrypter(SessionKey sessionKey, SessionIV sessionIV) throws Exception{
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKey;
        this.ivSpec = sessionIV.getSessionIV();
    }

    public CipherInputStream openCipherInputStream (InputStream input) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivSpec);
        return new CipherInputStream(input, cipher);
    }
}
