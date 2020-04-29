import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.io.IOException;


public class Client {

    private static DatagramSocket d;
    private static DatagramPacket DPreceived, DPsending;
    private static SecretKeySpec CK_A;
    private static Cipher AEScipher;
    private static byte[] received;
    public static boolean chatting = false;
    public static String sessionID;
    private static String clientID = "jas";
    private static String password = "password1";
    //private static String clientID = "rhs";
    //private static String password = "password2";


    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        /**** Setting up the UDP connectivity ****/

        Scanner input = new Scanner(System.in);

        // create the datagram socket and catch exception if cannot
        DatagramSocket d = null;
        try { d = new DatagramSocket(); }
        catch (SocketException e) {
            System.out.println("Couldn't create the UDP socket");
            System.exit(-1);
        }

        // Set the ip of the server.
        InetAddress ip = null;
        try { ip = InetAddress.getLocalHost(); } catch (UnknownHostException e) { e.printStackTrace(); }


        /**** UDP connectivity established, now sending/receiving messages ****/
        // variables for the control of the UDP messages exchanged
        String in, out, rand = "";
        String rand_cookie = "", TCP_port = "";
        boolean nextIsAUTH = false;

        // Loop until user types Log on and create the HELLO UDP message when they do
        System.out.println("Welcome: To sign on enter 'Log on' ");
        out = input.nextLine();
        while(!out.equalsIgnoreCase("Log on")){
            out= input.nextLine();
        }
        if (out.equalsIgnoreCase("Log on")) {
            out = "HELLO(" + clientID + ")";
        }

        // creates and sends a Datagram Packet to the server with the HELLO message
        DPsending = new DatagramPacket(out.getBytes("UTF-8"),out.length(),ip,12002);
        try { d.send(DPsending); } catch (IOException e) { System.exit(-1); }

        while(true){
            // buffer for data sent by the server
            received = new byte[65536];
            DPreceived = new DatagramPacket(received,received.length);

            // sets the timeout of the server
            try { d.setSoTimeout(10000); } catch (SocketException e) { e.printStackTrace(); }
            try { d.receive(DPreceived); } catch (IOException e) {
                System.out.println("Connection to the server timed out");
            }
            in = new String(DPreceived.getData(),StandardCharsets.US_ASCII);

            // if CHALLENGE received from server use the random value and run it through the A3 enryption method
            // and send the result of it back to the server with the RESPONSE message
            if(in.contains("CHALLENGE(")){
                int end = in.trim().length();
                rand = in.substring(10,end-1);
                String res = A3(rand, password);
                out = "RESPONSE(" + res + ")";
                nextIsAUTH = true;
                DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12002);
                try {
                    d.send(DPsending);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                out = "";
                continue;
            }

            // if AUTH_FAIL received then RESPONSE was incorrect exit the program
            if(in.contains("AUTH_FAIL")){
                System.out.println("Incorrect password .... exiting");
                System.exit(0);
            }
            // if invalid then user is not a registered user exit program
            if(in.contains("INVALID")){
                System.out.println("You are not a registered user");
                System.exit(0);
            }
            // if the user is already logged on indicate that and exit program
            if(in.contains("DENIED")){
                System.out.println("This user is already logged on");
                System.exit(0);
            }
            // RESPONSE was correct create the encryption key to encrypt/decrypt messages to/from server and break loop
            if(nextIsAUTH == true){
                // create encryption key
                CK_A = A8(rand, password);

                String w = null;
                try {
                    w = decrypt(CK_A, in.trim().getBytes("UTF-8"));
                } catch (Exception e) {
                    e.printStackTrace();
                }
                int end, comma_location;
                comma_location = w.indexOf(",");
                end = w.length();
                rand_cookie = w.substring(13,comma_location);
                TCP_port = w.substring(comma_location+1, end-1);

                break;
            }
        }

        // close the UDP datagram socket and start a new socket.
        d.close();
        try {
            startTCPconn(ip,rand_cookie,TCP_port);
        } catch (Exception e) {
            e.printStackTrace();
        }

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

        // spawns a new thread to listen to messages from the server
        Thread t = new ServerListener(s,CK_A,inbound,outbound);
        t.start();

        // all outbound messages must be encrypted and all inbound must be decrypted
        while(true){
            String input = in.nextLine();

            /******* FOLLOWING BLOCK INPUT COMMANDS IF NOT IN A CHAT *********/
            if(!chatting) {
                // sends a message to the server to indicate that the user is logging off
                if (input.equalsIgnoreCase("Log off")) {
                    sending = new String(encrypt(CK_A, input.toUpperCase()), StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                    break;
                }

                // sends a message to the server indicating the clients request to chat with another client
                if (input.length() > 15 && input.substring(0, 15).equalsIgnoreCase("Chat Client-ID-")) {
                    if(input.substring(15).equals(clientID))
                        System.out.println("You can't chat with yourself");
                    else {
                        String toSend = "CHAT_REQUEST(" + input.substring(5) + ")";
                        sending = new String(encrypt(CK_A, toSend), StandardCharsets.US_ASCII);
                        outbound.writeUTF(sending);
                    }
                    continue;
                }

                // sends a message to the server that the client wants chat history with a specific client
                if (input.length() > 18 && input.substring(0, 18).equalsIgnoreCase("History Client-ID-")) {
                    if(input.substring(18).equals(clientID))
                        System.out.println("You don't have chat history with yourself");
                    else{
                        String toSend = "HISTORY_REQ(" + input.substring(18) + ")";
                        sending = new String(encrypt(CK_A, toSend), StandardCharsets.US_ASCII);
                        outbound.writeUTF(sending);
                    }
                    continue;
                }

                // if the user doesn't input a valid command it still sends to update the timeout for the server
                sending = new String(encrypt(CK_A, input),StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
            }
            /***** Following Block for if in a Chat *******/
            if(chatting){
                if(input.equalsIgnoreCase("End chat")) {
                    String toSend = "END_REQUEST(" + sessionID + ")";
                    sending = new String(encrypt(CK_A, toSend), StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                    chatting = false;
                    System.out.println("Chat ended");
                }
                else if(input.length() > 15 && input.substring(0,15).equalsIgnoreCase("Chat Client-ID-")){
                    System.out.println("You must end the chat before chatting with a new client.");
                }
                else if(input.length() > 18 && input.substring(0,18).equalsIgnoreCase("History Client-ID-")){
                    System.out.println("You must end the chat before viewing your chat history.");
                }
                else if(input.equalsIgnoreCase("Log off")){
                    System.out.println("You must end the chat before logging off.");
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
    DataOutputStream outbound;
    SecretKeySpec CK_A;

    ServerListener(Socket s, SecretKeySpec CK_A, DataInputStream inbound,DataOutputStream outbound){
        this.s = s;
        this.CK_A = CK_A;
        this.inbound = inbound;
        this.outbound = outbound;
    }

    private void ping() throws Exception {
        String s = "PING()";
        s = new String(Client.encrypt(CK_A, s), StandardCharsets.US_ASCII);
        outbound.writeUTF(s);
    }

    public void run(){
        String received = "";
        while(true) {
            try {
                received = Client.decrypt(CK_A, inbound.readUTF().getBytes("UTF-8"));
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (received.contains("UNREACHABLE(")) {
                System.out.println("Correspondent Unreachable");
                continue;
            }

            if(received.contains("END_NOTIF(")){
                Client.chatting = false;
                System.out.println("Chat ended");
                try { ping(); } catch (Exception e) { e.printStackTrace(); }
                continue;
            }

            if(Client.chatting == true) {
                System.out.println(received);
                continue;
            }

            if (received.contains("CHAT_STARTED(") && Client.chatting == false) {
                System.out.print("You are now chatting with ");
                System.out.println(received.substring(received.indexOf(",") + 1, received.length() - 1));
                Client.chatting = true;
                Client.sessionID = received.substring(13, received.indexOf(","));
                try { ping(); } catch (Exception e) { e.printStackTrace(); }
                continue;
            }

            if(received.contains("HISTORY_RESP(")){
                if(received.length() == 14)
                    System.out.println("No chat history between you and the requested user");
                else
                    System.out.println(received.substring(13,received.length()-1));

                continue;
            }


            if(received.equals("EXIT()")){
                break;
            }

            if(received.equals("TIMEOUT()")){
                System.out.println("Disconnected due to inactivity");
                System.exit(0);
            }

            if(received.equals("SPAM()")){
                System.out.println("Disconnected due to possible spam");
                System.exit(0);
            }

            if(received.equals("INCORRECT()")){
                System.out.println("Incorrect Command, commands in the format of \n" +
                        "1) Chat Client-ID-\n2) History Client-ID-\n3) Log off");
                continue;
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

