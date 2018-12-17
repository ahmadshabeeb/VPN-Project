package network;

import other.Arguments;
import other.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;

    static Integer KEYLENGTH = 128;


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
    private static final String SERVER_HOST = "TargetHost";
    private static final String SERVER_PORT = "TargetPort";

    private static final String SERVER_CERT_PATH =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\server.pem";
    private static final String CA_CERT_PATH =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\ca.pem";
    private static final String SERVER_PRIVATE_KEY =  "C:\\Users\\Ahmad\\Desktop\\vpn-project\\src\\certs\\server-private.der";

    private ServerSocket handshakeSocket;
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {
        X509Certificate caCert = aCertificate.pathToCert(CA_CERT_PATH);

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ": " + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);

        // 2. receive a ClientHello
        System.out.println("2. receive a ClientHello");
        if (!clientHello.getParameter(MSGTYPE).equals(CLIENTHELLO)) {
            System.err.println("Received invalid handshake type! - connection is Terminated");
            clientSocket.close();
            throw new Error();
        }

        // 3. verify certificate is signed by our CA
        System.out.println("3. verify certificate is signed by our CA");
        String clientCertString = clientHello.getParameter(CERTIFCATE);
        X509Certificate clientCert = aCertificate.stringToCert(clientCertString);
        aCertificate.verifyCertificate(clientCert, caCert.getPublicKey());

        // 4. Send Server Hello
        System.out.println("4. Send Server Hello");
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter(MSGTYPE, SERVERTHELLO);
        serverHello.putParameter(CERTIFCATE, aCertificate.encodeCert(aCertificate.pathToCert(SERVER_CERT_PATH)));
        serverHello.send(clientSocket);

        // 8. receive a Forward msg
        System.out.println("8. receive a Forward msg");
        HandshakeMessage forwardMsg = new HandshakeMessage();
        forwardMsg.recv(clientSocket);

        if (!forwardMsg.getParameter(MSGTYPE).equals(FORWARD)) {
            System.err.println("Received invalid handshake type! - connection is Terminated");
            clientSocket.close();
            throw new Error();
        }

        // setting the desired Target by the Client
        Handshake.setTargetHost(forwardMsg.getParameter(TARGET_HOST));
        Handshake.setTargetPort(Integer.parseInt(forwardMsg.getParameter(TARGET_PORT)));

        // 9. generate the session
        System.out.println("9. generate the session");
        SessionIV sessionIV = new SessionIV();
        SessionKey sessionKey = new SessionKey(KEYLENGTH);

        String ivString = sessionIV.encodeIV();
        String sessionKeyString = sessionKey.encodeKey();

        // encrypt ivString and sessionKeyString
        PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(SERVER_PRIVATE_KEY);
        String encryptedIV =  HandshakeCrypto.encrypt(ivString.getBytes(), privateKey).toString();
        String encryptedSessionKey = HandshakeCrypto.encrypt(sessionKeyString.getBytes(), privateKey).toString();

        // 10. send session msg
        System.out.println("10. send session msg");
        HandshakeMessage sessionMsg = new HandshakeMessage();
        sessionMsg.putParameter(MSGTYPE, SESSION );
        sessionMsg.putParameter(SESSION_KEY, encryptedSessionKey);
        sessionMsg.putParameter(SESSION_IV, encryptedIV);
        sessionMsg.send(clientSocket);

        System.out.println("Server closing handshake with client");
        clientSocket.close();

        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = Handshake.targetHost;
        targetPort = Handshake.targetPort;        
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {

               doHandshake();

               forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
               forwardThread.start();
           } catch (IOException e) {
               throw e;
           }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}
