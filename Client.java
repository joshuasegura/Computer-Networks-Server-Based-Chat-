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


public class Client{

    private static DatagramSocket d;
    private static DatagramPacket DPreceived, DPsending;
    private static SecretKeySpec CK_A;
    private static Cipher AEScipher;
    private static byte[] received;
    public static boolean chatting = false;
    public static String sessionID;
    //private static String clientID = "jas151530";
    //private static String password = "password1";
    private static String clientID = "msn160030";
    private static String password = "password4";


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
                    out = "";
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

    private static void startTCPconn (InetAddress ip,String rand_cookie, String TCP_port) throws Exception {
        Socket s = new Socket(ip,Integer.parseInt(TCP_port));
        DataInputStream inbound = new DataInputStream(s.getInputStream());
        DataOutputStream outbound = new DataOutputStream(s.getOutputStream());
        String received, sending;
        Scanner in = new Scanner(System.in);

        // send the initial connect message
        String connect = "CONNECT(" + rand_cookie + ")";
        sending = new String(encrypt(CK_A,connect),StandardCharsets.US_ASCII);
        outbound.writeUTF(sending);

        // receiving initial message indicating that user is connected
        received = decrypt(CK_A,inbound.readUTF().getBytes("UTF-8"));
        if(received.equals("CONNECTED"))
            System.out.println("You are connected");

        ////// put the listener class info here
        Thread t = new ServerListener(s,CK_A,inbound);
        t.start();

        // all outbound messages must be encrypted and all inbound must be decrypted
        while(true){
            String input = in.nextLine();
            if(input.equals("Log off")) {
                sending = new String(encrypt(CK_A,input),StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
                break;
            }

            if(input.contains("Chat Client-ID-")){
                String toSend = "CHAT_REQUEST(" + input.substring(5) + ")";
                sending = new String(encrypt(CK_A,toSend),StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
            }

            /////// sending the chat message ///////
            if(chatting){
                if(input.equals("End chat")) {
                    String toSend = "END_REQUEST(" + sessionID + ")";
                    sending = new String(encrypt(CK_A, toSend), StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                    chatting = false;
                    System.out.println("Chat ended");
                }
                else {
                    String toSend = "CHAT("+ sessionID + "," + input + ")";
                    sending = new String(encrypt(CK_A, toSend), StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                }
            }

        }
        t.join();
        s.close();
    }

    // function for encryption of messages
    public static byte[] encrypt(SecretKeySpec myKey, String message) throws Exception {
        AEScipher = Cipher.getInstance("AES");
        AEScipher.init(Cipher.ENCRYPT_MODE, myKey);
        byte[] toEncrypt = message.getBytes("UTF-8");
        byte[] encrypted = Base64.getEncoder().encode(AEScipher.doFinal(toEncrypt));

        String encryptedString = new String(encrypted,StandardCharsets.US_ASCII);
        return encrypted;
    }

    // function for decrypting received messages
    public static String decrypt(SecretKeySpec myKey, byte[] message) throws Exception{
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

class ServerListener extends Thread{
    Socket s;
    DataInputStream inbound;
    SecretKeySpec CK_A;

    ServerListener(Socket s, SecretKeySpec CK_A, DataInputStream inbound){
        this.s = s;
        this.CK_A = CK_A;
        this.inbound = inbound;
    }

    public void run(){
        String received = "";
        System.out.println("In client thread");
        while(true){
            try {
                received = Client.decrypt(CK_A,inbound.readUTF().getBytes("UTF-8"));
            } catch (Exception e) {
                e.printStackTrace();
            }

            if(received.contains("UNREACHABLE(")){
                System.out.println("Correspondent Unreachable");
            }

            if(received.contains("CHAT_STARTED(")) {
                System.out.print("You are now chatting with ");
                System.out.println(received.substring(received.indexOf(",")+1,received.length()-1));
                Client.chatting = true;
                Client.sessionID = received.substring(13,received.indexOf(","));
                System.out.println("SessionID: " + Client.sessionID);
                System.out.println(received);
                continue;
            }

            if(received.contains("END_NOTIF(")){
                Client.chatting = false;
                System.out.println("Chat ended");
            }

            if(Client.chatting == true)
                System.out.println(received);

            if(received.equals("EXIT()")){
                break;
            }

        }

        // close the input stream before returning
        try {
            inbound.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

