import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class ServerwithCP1 {

    public static void main(String[] args) throws Exception {

        int port = 4321;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        // obtain server certificate
        InputStream fis = new FileInputStream(
                "C:/Users/User/Documents/GitHub/ProgrammingAssignment2/PA2/docs2/certificate_1004286.crt");
        // "C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\certificate_1004286.crt");
        X509Certificate ServerCert = getCertificate(fis);
        System.out.println(ServerCert.getPublicKey());
        // PublicKey serverPublicKey;
        // serverPublicKey =
        // PublicKeyReader.get("C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\public_key.der");
        // System.out.println(serverPublicKey);

        // extract private key from file
        PrivateKey serverPrivateKey;
        serverPrivateKey = PrivateKeyReader
                .get("C:/Users/User/Documents/GitHub/ProgrammingAssignment2/PA2/docs2/private_key.der");
        // .get("C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\private_key.der");

        // System.out.println(serverPrivateKey);

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            int packet = 0;

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    packet = 0; // initialize packet size to be 0
                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte[] filename = new byte[numBytes];
                    // Must use read fully!
                    // See:
                    // https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);
                    if (!(new String(filename, 0, numBytes)).equals("port")
                            || !isNumeric(new String(filename, 0, numBytes))) {
                        File file = new File(new String(filename, 0, numBytes));
                        fileOutputStream = new FileOutputStream("recv_" + file.getName());
                        bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    }

                    // If the packet is for transferring a chunk of the file
                }
                if (packetType == 1) {

                    int numBytes = fromClient.readInt();
                    int EncryptednumBytes = fromClient.readInt();

                    byte[] block = new byte[EncryptednumBytes];
                    fromClient.readFully(block, 0, EncryptednumBytes);
                    // byte[] block = new byte[numBytes];
                    // fromClient.readFully(block,0,numBytes);

                    packet++;

                    byte[] decryptedblock = decrypt(block, serverPrivateKey);

                    // System.out.println(decryptedblock.length);

                    if (numBytes > 0) {
                        // connectionSocket.setKeepAlive(true);
                        bufferedFileOutputStream.write(decryptedblock, 0, numBytes);

                    }
                    if (numBytes < 117) {
                        toClient.writeInt(20);
                        System.out.println("File is received");
                        if (bufferedFileOutputStream != null) {
                            bufferedFileOutputStream.close();
                            fileOutputStream.close();

                        }

                    }
                }
                // If packet is requesting encrypted nonce
                else if (packetType == 2) {
                    System.out.println("client requested for authentication");
                    String nonce = fromClient.readUTF();
                    System.out.println(nonce);
                    byte[] encryptednonce = encrypt(nonce.getBytes(), serverPrivateKey);
                    System.out.println(Arrays.toString(encryptednonce));
                    toClient.write(encryptednonce);
                    System.out.println("sent encrypted nonce");
                }
                // If packet is requesting for server certificate
                else if (packetType == 3) {
                    System.out.println("client requested for certificate");
                    toClient.writeUTF(Base64.getEncoder().encodeToString(ServerCert.getEncoded()));
                }
                // If packet sends data that client closed connection
                else if (packetType == 4) {
                    System.out.println("Closing connection...");
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();

                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] encrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // encrypt message
        return cipher.doFinal(byteArray);
    }

    public static byte[] decrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cypher
        Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decipher.init(Cipher.DECRYPT_MODE, key);

        // decrypt message
        return decipher.doFinal(byteArray);
    }

    public static boolean isNumeric(String str) {
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static X509Certificate getCertificate(InputStream is) throws CertificateException {
        X509Certificate CAcert = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CAcert = (X509Certificate) cf.generateCertificate(is);

        } catch (CertificateException e) {
            System.out.println("Certificate expired");

        }

        return CAcert;
    }

}