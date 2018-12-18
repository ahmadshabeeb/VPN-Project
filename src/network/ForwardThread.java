package network;

/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class ForwardThread extends Thread
{
private static final int READ_BUFFER_SIZE = 8192;

/**
 * CRYPTO_MODE
 * ENCRYPTION MODE = 0
 * DECRYPTION MODE = 1
 * */
private int CRYPTO_MODE = -1;
private int ENCRYPTION_MODE = 0;
private int DECRYPTION_MODE = 1;
private int vpnType = 0;
 
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
    ForwardServerClientThread mParent = null;

    SessionEncrypter sessionEncrypter;
    SessionDecrypter sessionDecrypter;
 
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, int cryptoMode) throws Exception {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        this.CRYPTO_MODE = cryptoMode;
        this.sessionEncrypter = new SessionEncrypter(Handshake.sessionKey, Handshake.sessionIV);
        this.sessionDecrypter = new SessionDecrypter(Handshake.sessionKey, Handshake.sessionIV);
    }
 
    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run()
    {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        try {
            while (true) {
                //mOutputStream.write(buffer, 0, bytesRead);
                if(CRYPTO_MODE == ENCRYPTION_MODE) {
                    System.out.println("ENCRYPTING");
                    int bytesRead = mInputStream.read(buffer);

                    System.out.println(new String(buffer, "UTF-8"));
                    if (bytesRead == -1)
                        break; // End of stream is reached --> exit the thread

                    CipherOutputStream cryptoout = this.sessionEncrypter.openCipherOutputStream(mOutputStream);
                    cryptoout.write(buffer, 0, bytesRead);

                } else if (CRYPTO_MODE == DECRYPTION_MODE) {
                    System.out.println("DECRYPTING");
                    CipherInputStream cryptoin = this.sessionDecrypter.openCipherInputStream(mInputStream);
                    System.out.println(new String(buffer, "UTF-8"));
                    int bytesRead = cryptoin.read(buffer);
                    if (bytesRead == -1)
                        break; // End of stream is reached --> exit the thread
                    mOutputStream.write(buffer, 0, bytesRead);
                }
                //mOutputStream.write(buffer, 0, bytesRead);
//                while ((bytesRead = mInputStream.read()) != -1) {
//                    mOutputStream.write(bytesRead);
//                }
            }
        } catch (Exception e) {
            // Read/write failed --> connection is broken --> exit the thread
        }
 
        // Notify parent thread that the connection is broken and forwarding should stop
        mParent.connectionBroken();
    } 
}
