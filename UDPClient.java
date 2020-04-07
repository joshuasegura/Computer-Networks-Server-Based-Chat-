import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
        String rand_cookie = "", TCP_port = "";
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
                    int end, comma_location;
                    comma_location = w.indexOf(",");
                    end = w.length();
                    rand_cookie = w.substring(13,comma_location);
                    TCP_port = w.substring(comma_location+1, end-1);

                    break;
                }

            }
            else
                break;
        }
        d.close();
        startTCPconn(ip,rand_cookie,TCP_port);
    }

    private static void startTCPconn(InetAddress ip,String rand_cookie, String TCP_port) throws Exception {
        Socket s = new Socket(ip,Integer.parseInt(TCP_port));
        DataInputStream inbound = new DataInputStream(s.getInputStream());
        DataOutputStream outbound = new DataOutputStream(s.getOutputStream());
        String received, sending;
        Scanner in = new Scanner(System.in);

        // send the initial connect message
        String connect = "CONNECT(" + rand_cookie + ")";
        sending = new String(encrypt(CK_A,connect),StandardCharsets.US_ASCII);
        outbound.writeUTF(sending);

        received = decrypt(CK_A,inbound.readUTF().getBytes("UTF-8"));
        if(received.equals("CONNECTED"))
            System.out.println("You are connected");
        // all outbound messages must be encrypted and all inbound must be decrypted
        while(true){
            String input = in.nextLine();
            if(input.equals("Log out")) {
                sending = new String(encrypt(CK_A,input),StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
                break;
            }
        }

        s.close();
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

