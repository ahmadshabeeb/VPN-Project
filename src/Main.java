import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main (String[] args) throws Exception {
        testSessionKey();
    }

    public static void testSessionKey() throws Exception {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        if (key1.getSecretKey().equals(key2.getSecretKey())) {
            System.out.println("Pass");
        }
        else {
            System.out.println("Fail");
        }
    }
}
