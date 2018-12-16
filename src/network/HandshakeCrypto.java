package network;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


public class HandshakeCrypto {

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream file = new FileInputStream (certfile);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(file);
        PublicKey publicKey =  cer.getPublicKey();
        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String privatekeyfile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Path path = Paths.get(privatekeyfile);
        byte[] privateKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static byte[] encrypt(byte[] plainInputBytes, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(plainInputBytes);
        return cipherData;
    }

    public static byte[] decrypt(byte[] cipheredInputBytes, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainData = cipher.doFinal(cipheredInputBytes);
        return plainData;
    }
}
