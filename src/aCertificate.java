import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class aCertificate {
    public static X509Certificate pathToCert(String certPath) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream CAIs = new FileInputStream(certPath);
        return  (X509Certificate) fact.generateCertificate(CAIs);
    }

    public static X509Certificate stringToCert(String certString) throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(certString.getBytes());
        return (X509Certificate) fact.generateCertificate(inputStream);
    }

    public static String encodeCert(X509Certificate cert) throws Exception {
        String LINE_SEPARATOR = System.getProperty("line.separator");
        String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
        String END_CERT = "-----END CERTIFICATE-----";

        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        byte[] rawCrtText = cert.getEncoded();
        String encodedCertText = new String(encoder.encode(rawCrtText));
        return BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;
    }

    static boolean verifyCertificate(X509Certificate cer, PublicKey publicKey) {
        try {
            cer.checkValidity();
        } catch (Exception e) {
            System.out.println("Certificate expired");
            e.printStackTrace();
        }

        try {
            cer.verify(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }
}