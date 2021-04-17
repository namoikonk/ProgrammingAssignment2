import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class ClientwithCP1 {
    public static void main(String[] args) throws FileNotFoundException, CertificateException {

        // get CA's public key for verification
        InputStream fis = new FileInputStream(
                "C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\docs2\\cacsertificate.crt");
        X509Certificate CAcert = getCertificate(fis);
        PublicKey CAKey = CAcert.getPublicKey();

        /*
         * String filename =
         * "C:\\Users\\dksat\\Documents\\GitHub\\ProgrammingAssignment2\\PA2\\500.txt";
         * if (args.length > 0) filename = args[0];
         */

        String serverAddress = "localhost";
        /*
         * if (args.length > 1) filename = args[1];
         */

        int port = 8080;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("port")) {
                port = Integer.parseInt(args[i + 1]);
            }
        }

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        try {
            // Connect to server and get the input and output streams
            System.out.println("Connecting to server...");
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            System.out.println("Authenticating...");

            // send nonce to server and request for encrypted nonce
            toServer.writeInt(2);
            Random rand = new Random();
            String nonce = generateString(rand, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 8);
            System.out.println(nonce);
            toServer.writeUTF(nonce);

            // receive encrypted nonce with server's private key
            byte[] encryptednonce = new byte[128];
            int no_bytes_read = fromServer.read(encryptednonce);
            System.out.println(no_bytes_read);

            // ask for signed certificate
            toServer.writeInt(3);
            System.out.println("Requesting server certificate");
            String certString = fromServer.readUTF();

            // create X509Certificate object
            byte[] bytes = Base64.getDecoder().decode(certString);
            InputStream bis = new ByteArrayInputStream(bytes);

            X509Certificate ServerCert = getCertificate(bis);

            // get server public key
            PublicKey serverPublicKey = ServerCert.getPublicKey();
            System.out.println("serverPublicKey: " + serverPublicKey);

            // verify signed certificate
            ServerCert.checkValidity();
            ServerCert.verify(CAKey);

            // decrypt and compare nonce with decryptednonce
            byte[] decryptednonce = decrypt(encryptednonce, serverPublicKey);

            if (!equalsNonce(nonce.getBytes(), decryptednonce)) {
                // close server connection if verification fails
                toServer.writeInt(4);
                System.out.println("Not authentic server, closing connection...");
                return;
            }

            System.out.println("Server's certificate is verified!");

            System.out.println("Establishing connection to server...");

            for (int i = 0; i < args.length; i++) {
                System.out.println("Sending file...");
                if (args[i].equals("port")) {
                    toServer.writeInt(4);
                    bufferedFileInputStream.close();
                    fileInputStream.close();
                    break;
                }

                String filename = args[i];

                // send the filename
                toServer.writeInt(0);
                toServer.writeInt(filename.getBytes().length);
                toServer.write(filename.getBytes());
                toServer.flush();

                // open the file
                fileInputStream = new FileInputStream(filename);
                bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                byte[] fromFileBuffer = new byte[117];

                // send the file
                for (boolean fileEnded = false; !fileEnded;) {
                    numBytes = bufferedFileInputStream.read(fromFileBuffer);
                    fileEnded = numBytes < 117;

                    toServer.writeInt(1);

                    // encrypt file
                    byte[] encryptedfromFileBuffer = encrypt(fromFileBuffer, serverPublicKey);
                    int encyrptednumBytes = encryptedfromFileBuffer.length;

                    // send encrypted file
                    toServer.writeInt(numBytes);
                    toServer.writeInt(encyrptednumBytes);
                    toServer.write(encryptedfromFileBuffer);
                    toServer.flush();

                }
                System.out.println("File sent");

                if (i == args.length - 1) {
                    System.out.println("Closing connection...");
                    toServer.writeInt(4);
                    bufferedFileInputStream.close();
                    fileInputStream.close();
                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
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

    // global functions

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

    public static String generateString(Random rng, String characters, int length) {
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = characters.charAt(rng.nextInt(characters.length()));
        }
        return new String(text);
    }

    public static boolean equalsNonce(byte[] nonce, byte[] decryptedNonce) {
        return Arrays.equals(nonce, decryptedNonce);
    }

}
