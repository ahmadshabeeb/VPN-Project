package network;

import other.Arguments;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardClient
{
    static Integer KEYLENGTH = 128;
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static final String MSGTYPE = "MessageType";
    private static final String CERTIFCATE = "Certificate";
    private static final String CLIENTHELLO = "ClientHello";
    private static final String SERVERTHELLO = "ServerHello";
    private static final String FORWARD = "Forward";
    private static final String SESSION = "Session";
    private static final String SESSION_KEY = "SessionKey";
    private static final String SESSION_IV = "SessionIV";
    private static final String TARGET_HOST = "TargetHost";
    private static final String TARGET_PORT = "TargetPort";

    private static final String CLIENT_CERT_PATH =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\client.pem";
    private static final String SERVER_CERT_PATH =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\server.pem";
    private static final String CA_CERT_PATH     =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\ca.pem";
    private static final String CLIENT_PRIVATE_KEY =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\client-private.der";

    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private static SessionKey sessionKey;
    private static SessionIV sessionIV;

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args)
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    private static void doHandshake() throws Exception {
        X509Certificate caCert = aCertificate.pathToCert(CA_CERT_PATH);

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */

        // 1. Send ClientHello
        System.out.println("1. Send ClientHello");
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter(MSGTYPE, CLIENTHELLO);
        clientHello.putParameter(CERTIFCATE, aCertificate.encodeCert(aCertificate.pathToCert(CLIENT_CERT_PATH)));
        clientHello.send(socket);

        // 5. receive a ServerHello
        System.out.println("5. receive a ServerHello");
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);

        if (!serverHello.getParameter(MSGTYPE).equals(SERVERTHELLO)) {
            System.err.println("Received invalid handshake type! - connection is Terminated");
            socket.close();
            throw new Error();
        }

        // 6. Verify server certificate is signed by our CA
        System.out.println("6. Verify server certificate is signed by our CA");
        String serverCertString = clientHello.getParameter(CERTIFCATE);
        X509Certificate serverCert = aCertificate.stringToCert(serverCertString);
        aCertificate.verifyCertificate(serverCert, caCert.getPublicKey());

        // 7. send forward msg
        System.out.println("7. send forward msg");
        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.putParameter(MSGTYPE, FORWARD);
        forwardMessage.putParameter(TARGET_HOST, arguments.get("targethost"));
        forwardMessage.putParameter(TARGET_PORT, arguments.get("targetport"));
        forwardMessage.send(socket);

        // 11. receive session msg
        System.out.println("11. receive session msg");
        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(socket);

        if (!sessionMessage.getParameter(MSGTYPE).equals(SESSION)) {
            System.err.println("Received invalid handshake type! - connection is Terminated");
            socket.close();
            throw new Error();
        }

        // 12. get session parameters
        PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(CLIENT_PRIVATE_KEY);

        // decode and decrypt session key
        String encodedKeyString = sessionMessage.getParameter(SESSION_KEY);
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encodedKeyString);
        byte[] decryptedKeyBytes = HandshakeCrypto.decrypt(encryptedKeyBytes, clientPrivateKey);
        String encodedSessionKey = new String(decryptedKeyBytes, ENCODING);
        System.out.println("Sessionkey: " + encodedSessionKey);
        sessionKey = new SessionKey(encodedSessionKey);

        // decode and decrypt session IV
        String encodedIvString = sessionMessage.getParameter(SESSION_IV);
        byte[] encryptedIvBytes = Base64.getDecoder().decode(encodedIvString);
        byte[] decryptedBytes = HandshakeCrypto.decrypt(encryptedIvBytes, clientPrivateKey);
        String encodedSessionIV = new String(decryptedBytes, ENCODING);
        System.out.println("SessionIV: " + encodedSessionIV);

        System.out.println("Client close handshake");
        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;        
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);
            
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.start();
            
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }

}
