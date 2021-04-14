import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;


public class ClientwithCP1 {
    public static void main(String[] args) throws FileNotFoundException, CertificateException {

        //get CA's public key for verification
        InputStream fis = new FileInputStream("docs2/cacsecertificate.crt");
        X509Certificate CAcert = getCertificate(fis);
        PublicKey CAKey = CAcert.getPublicKey();


        String filename = "100.txt";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        try {
            System.out.println("Autheniticating...");

            //send nonce to server and request for encrypted nonce
            toServer.writeInt(2);
            String nonce = RandomString.nextString();
            System.out.println(nonce);
            toServer.writeUTF(nonce);

            //receive encrypted nonce with server's private key
            String encryptedMessage = fromServer.readUTF();

            //ask for signed certificate
            toServer.writeInt(3);
            System.out.println("requesting server certificate");
            String certString = fromServer.readUTF();

            //create X509Certificate object
            byte[] bytes = Base64.getDecoder().decode(certString);
            InputStream bis = new ByteArrayInputStream(bytes);

            X509Certificate ServerCert = getCertificate(bis);

            // get server public key
            PublicKey serverPublicKey = ServerCert.getPublicKey();
            System.out.println("serverPublicKey: " + serverPublicKey);

            //verify signed certificate
            ServerCert.checkValidity();
            ServerCert.verify(CAKey);

            //decrypt and compare nonce with decryptednonce
            String decryptednonce = Base64.getEncoder().encodeToString(decrypt(Base64.getDecoder().decode(encryptedMessage), serverPublicKey));
            if(decryptednonce!= nonce){
                //close server connection
                toServer.writeInt(4);
                System.out.println("Not Authentic Server, Closing Connection...");
                return;
            }

            System.out.println("Server's certificate is verified!");

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            System.out.println("Sending file...");

            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());
            //toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte[] fromFileBuffer = new byte[117];

            // Send the file
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;

                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.write(fromFileBuffer);
                toServer.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

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
            System.out.println("certificate expired");

        }


        return CAcert;
    }


    public static byte[] decrypt(byte[] byteArray, Key key) throws Exception {
        // instantiate cypher
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(Cipher.DECRYPT_MODE, key);

        // System.out.println("BytesArray: " + byteArray + "\nLength of BytesArray: " + byteArray.length);

        // decrypt message
        byte[] decryptedBytesArray = desCipher.doFinal(byteArray);
        // System.out.println("decryptedBytesArray: " + decryptedBytesArray + "\nLength of decryptedBytesArray: "
        // + decryptedBytesArray.length);

        return decryptedBytesArray;
    }


}
