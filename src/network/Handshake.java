package network;

import java.security.PublicKey;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    public static final String serverHost = "localhost";
    public static final int serverPort = 4412;

    /* The final destination */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    public static SessionKey sessionKey;
    public static SessionIV sessionIV;

    public static void checkMsgType (HandshakeMessage msg, String msgType) {
        if (!msg.getParameter("MessageType").equals(msgType)) {
            System.err.println("Received invalid handshake message type! " + msg.getParameter("MessageType"));
            throw new Error();
        }
    }

    public static byte[] encryptSessionKey(SessionKey sessionKey, PublicKey publicKey) throws Exception {
        String sessionKeyString = sessionKey.encodeKey();
        byte[] sessionKeyBytes = sessionKeyString.getBytes("UTF-8");
        byte[] encryptedBytes = HandshakeCrypto.encrypt(sessionKeyBytes, publicKey);
        return encryptedBytes;
    }

    public static byte[] encryptSessionIV(SessionIV sessionIV, PublicKey publicKey) throws Exception {
        String sessionIvString = sessionIV.encodeIV();
        byte[] sessionIvBytes = sessionIvString.getBytes("UTF-8");
        byte[] encryptedBytes = HandshakeCrypto.encrypt(sessionIvBytes, publicKey);
        return encryptedBytes;
    }
}
