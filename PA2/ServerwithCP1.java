import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ServerwithCP1 {

    public static void main(String[] args) throws Exception {

        int port = 8080;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        //obtain server certificate
        InputStream fis = new FileInputStream("C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\certificate_1004286.crt");
        X509Certificate ServerCert = ClientwithCP1.getCertificate(fis);
        System.out.println(ServerCert.getPublicKey());
//        PublicKey serverPublicKey;
//        serverPublicKey = PublicKeyReader.get("C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\public_key.der");
//        System.out.println(serverPublicKey);


        //extract private key from file
        PrivateKey serverPrivateKey;
        serverPrivateKey = PrivateKeyReader.get("C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\private_key.der");
        //System.out.println(serverPrivateKey);


        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    int numBytes = fromClient.readInt();
                    byte [] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(block, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }
                //If packet is requesting encrypted nonce
                else if (packetType==2){
                    System.out.println("client requested for authentication");
                    String nonce = fromClient.readUTF();
                    System.out.println(nonce);
                    String encryptednonce = Base64.getEncoder().encodeToString(encrypt(nonce.getBytes(), serverPrivateKey));
                    System.out.println(encryptednonce);
                    toClient.writeUTF(encryptednonce);
                    System.out.println("sent encrypted nonce");
                }
                //If packet is requesting for server certificate
                else if (packetType==3){
                    System.out.println("client requested for authentication");
                    toClient.writeUTF(Base64.getEncoder().encodeToString(ServerCert.getEncoded()));
                }
                //If packet sends data that client closed connection
                else if (packetType==4){
                    System.out.println("Invalid Authentication, client has closed connection.");
                }

            }
        } catch (Exception e) {e.printStackTrace();}

    }

    public static byte[] encrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cipher
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, key);
        // System.out.println("BytesArray: " + byteArray + "\nLength of BytesArray: " + byteArray.length);


        // encrypt message
        byte[] encryptedBytesArray = rsaCipher.doFinal(byteArray);
        // System.out.println("encryptedBytesArray: " + encryptedBytesArray + "\nLength of encryptedBytesArray: "
        // + encryptedBytesArray.length);

        return encryptedBytesArray;
    }

}