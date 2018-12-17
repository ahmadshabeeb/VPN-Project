package tests;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.*;

public class VerifyCertificate {
    static private X509Certificate caCer;
    static private X509Certificate userCer;
    static private PublicKey caPublicKey;

    static public void main (String args[]) throws Exception {
        caCer = getCertificate(args[0]);
        caPublicKey = caCer.getPublicKey();
        userCer = getCertificate(args[1]);

        printSubjectDN("Subject DN for CA:   ", caCer);
        printSubjectDN("Subject DN for User: ", userCer);

        if(verifyCertificate(caCer, caPublicKey) && verifyCertificate(userCer, caPublicKey)) {
            System.out.println("PASS");
        } else {
            System.out.println("FAIL");
        }
    }

    static  X509Certificate getCertificate(String Stringfile) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream file = new FileInputStream (Stringfile);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(file);
        return cer;
    }

    static void printSubjectDN(String msg, X509Certificate cer) {
        System.out.println(msg + cer.getSubjectDN());
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
