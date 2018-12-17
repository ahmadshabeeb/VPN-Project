package network;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionIV {
    private IvParameterSpec ivParameterSpec;
    private byte[] iv;

    public SessionIV() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom randomSecureRandom = new SecureRandom();
        iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public SessionIV (String stringIV) throws Exception {
        iv = Base64.getDecoder().decode(stringIV);
        //decodeIV();
    }

    public IvParameterSpec getSessionIV() {
        return ivParameterSpec;
    }

    public String encodeIV() {
        return Base64.getEncoder().encodeToString(iv);
    }

    private void decodeIV() {
        ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
    }
}
