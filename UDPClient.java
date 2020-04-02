import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.io.IOException;


public class UDPClient {

    private static DatagramSocket d;
    private static DatagramPacket DPreceived, DPsending;
    private static SecretKeySpec CK_A;
    private static Cipher AEScipher;
    private static byte[] received;
    private static String clientID = "jas151530";
    private static String password = "password1";


    public static void main(String[] args) throws Exception{
        /**** This is the UDP client code ****/

        Scanner input = new Scanner(System.in);

        // create the datagram socket
        DatagramSocket d = new DatagramSocket();
        InetAddress ip = InetAddress.getLocalHost();
        String in, out, rand = "";
        boolean nextIsAUTH = false;

        System.out.println("This is just to get the UDP authentication working just type 'Log on' \n\tand" +
                " follow the steps from there, the password for now is just password" );
        out = input.nextLine();

        while(true){
            if(!out.equals("bye")){
                if (out.equals("Log on")) {
                    out = "HELLO(" + clientID + ")";
                }

                // sends the packet to the server
                DPsending = new DatagramPacket(out.getBytes("UTF-8"),out.length(),ip,12002);
                d.send(DPsending);

                // buffer for data sent by the server
                received = new byte[65536];
                DPreceived = new DatagramPacket(received,received.length);
                d.receive(DPreceived);
                System.out.println(DPreceived.getData());
                in = new String(DPreceived.getData(),StandardCharsets.US_ASCII);
                System.out.println(in);
                System.out.println(in.trim());


                if(in.contains("CHALLENGE(")){
                    int end = in.trim().length();
                    rand = in.substring(10,end-1);
                    String res = A3(rand, password);
                    out = "RESPONSE(" + res + ")";
                    nextIsAUTH = true;
                    DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12002);
                    d.send(DPsending);
                    continue;
                }
                if(in.contains("AUTH_FAIL")){
                    System.out.println("Incorrect password .... exiting");
                    break;
                }
                if(nextIsAUTH == true){
                    // create encryption key
                    CK_A = A8(rand, password);

                    String w = decrypt(CK_A, in.trim().getBytes("UTF-8"));
                    System.out.println(w);
                    System.out.println("Password correct");
                    System.out.println("\tStill need to create the cookie and port number part here\n" +
                            "\tas well as create the encrypted channel for communication -JS");
                    break;
                }

                System.out.println("Server: " + in);
            }
            else
                break;
        }
        d.close();
        System.out.println("out of client loop");
    }

    // function for encryption of messages
    private static byte[] encrypt(SecretKeySpec myKey, String message) throws Exception {
        AEScipher = Cipher.getInstance("AES");
        AEScipher.init(Cipher.ENCRYPT_MODE, myKey);
        byte[] toEncrypt = message.getBytes("UTF-8");
        byte[] encrypted = Base64.getEncoder().encode(AEScipher.doFinal(toEncrypt));

        String encryptedString = new String(encrypted,StandardCharsets.US_ASCII);
        return encrypted;
    }

    // function for decrypting received messages
    private static String decrypt(SecretKeySpec myKey, byte[] message) throws Exception{
        message = Base64.getDecoder().decode(message);
        AEScipher = Cipher.getInstance("AES");
        AEScipher.init(Cipher.DECRYPT_MODE,myKey);
        byte[] decrypted = AEScipher.doFinal(message);

        String decryptedString = new String(decrypted,StandardCharsets.US_ASCII);
        return decryptedString;
    }

    private static String A3(String rand, String password) throws NoSuchAlgorithmException {
        String hash = rand + password;
        // using SHA-256 for this hash
        MessageDigest m = MessageDigest.getInstance("SHA-256");
        m.update(hash.getBytes(StandardCharsets.UTF_8));
        byte[] hashed = m.digest();

        // convert the hashed result back into a String
        BigInteger num = new BigInteger(1,hashed);
        StringBuilder hex = new StringBuilder(num.toString(16));
        while(hex.length() < 32){
            hex.insert(0,'0');
        }

        String done = hex.toString();

        return done;
    }

    // This is the method that uses a hash function to generate the encryption key
    private static SecretKeySpec A8(String rand, String password) throws NoSuchAlgorithmException{
        String hash = rand + password;

        // using SHA-1 for this hash
        MessageDigest m = MessageDigest.getInstance("SHA-1");
        m.update(hash.getBytes(StandardCharsets.UTF_8));
        byte[] hashed = m.digest();
        hashed = Arrays.copyOf(hashed,16);

        // Store in encryption key and return the value of it
        SecretKeySpec key = new SecretKeySpec(hashed, "AES");
        return key;
    }

}

