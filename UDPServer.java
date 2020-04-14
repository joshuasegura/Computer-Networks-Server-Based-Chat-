import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Arrays;
import java.util.ArrayList;

public class UDPServer {


    private static DatagramSocket d;
    private static DatagramPacket DPreceived,DPsending;
    private static byte[] received;
    private static Cipher AEScipher;
    private static SecretKeySpec CK_A;
    private static String validate_user;
    public static ArrayList<String> real_users = new ArrayList<String>(){
        {
            add("jas151530");
            add("rhs160030");
            add("hzs170003");
            add("msn160030");
        }
    };
    public static ArrayList<String> passwords = new ArrayList<String>(){
        {
            add("password1");
            add("password2");
            add("password3");
            add("password4");
        }
    };
    private static String Xres;

    public static void main(String[] args) throws Exception{
        /**** This is the server for the chat system  ****/

        // new datagram socket at port 12000
        d = new DatagramSocket(12002);
        new TCPhandler();
        Random random = new Random();
        int rand = 0, index = 0;
        String in,out = null;
        int client_port;
        InetAddress client_Address;
        boolean skip = false;

        while(true){
            received = new byte[65536];
            DPreceived = new DatagramPacket(received, received.length);
            d.receive(DPreceived);
            client_Address = DPreceived.getAddress();
            client_port = DPreceived.getPort();
            in = new String(DPreceived.getData()).trim();

            if(in.contains("HELLO(")){
                int end = in.length();
                validate_user = in.substring(6,end-1);
                if(real_users.contains(validate_user)){
                    index = real_users.indexOf(validate_user);
                    rand = random.nextInt(); // generates the random number
                    Xres = A3(rand, passwords.get(index));
                    out = "CHALLENGE(" + rand + ")";
                }
                else
                    out = validate_user + " isn't a valid user";
            }
            else if(in.contains("RESPONSE(")){
                String res = in.substring(9,in.length()-1);
                if(res.equals(Xres) ){
                    CK_A = A8(rand,passwords.get(index));
                    client_Address = DPreceived.getAddress();
                    int rand_cookie = random.nextInt();
                    int TCPport = random.nextInt((65535+1) - 1023) + 1023;
                    byte[] encrypted = encrypt(CK_A, "AUTH_SUCCESS(" + rand_cookie +"," + TCPport + ")");
                    received = new byte[encrypted.length];
                    received = encrypted;
                    skip = true;
                    createTCPconnection(rand_cookie,TCPport,CK_A,client_Address,validate_user);

                    //// create the TCP connection thread here /////
                    //Thread thr = new TCPhandler(rand_cookie,TCPport);
                    //thr.start();
                }
                else
                    out = "AUTH_FAIL";
            }

            if(in.contains("bye"))
                break;

            if(skip == false){
                DPsending = new DatagramPacket(out.getBytes(),out.length(),client_Address,client_port);
                d.send(DPsending);
            }
            else{
                skip = false;
                DPsending = new DatagramPacket(received,received.length,client_Address,client_port);
                System.out.println(DPsending.getData());
                d.send(DPsending);
            }

        }
        System.out.println("out of server loop");
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

    // This is the authentication algorithm for the UDP user verification
    private static String A3(int rand, String password) throws NoSuchAlgorithmException {
        String hash = Integer.toString(rand) + password;
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
    private static SecretKeySpec A8(int rand, String password) throws NoSuchAlgorithmException{
        String hash = Integer.toString(rand) + password;

        // using SHA-1 for this hash
        MessageDigest m = MessageDigest.getInstance("SHA-1");
        m.update(hash.getBytes(StandardCharsets.UTF_8));
        byte[] hashed = m.digest();
        hashed = Arrays.copyOf(hashed,16);

        // Store in encryption key and return the value of it
        SecretKeySpec key = new SecretKeySpec(hashed, "AES");
        return key;
    }

    // This method creates the TCP connection
    private static void createTCPconnection(int rand_cookie,int TCPport,SecretKeySpec CK_A,
                                    InetAddress ip, String validate_user){

        Thread thr = new TCPhandler(rand_cookie,TCPport,CK_A,validate_user);
        thr.start();
    }
}

class TCPhandler extends Thread{
    public static ArrayList<Integer> clientSession;
    public static ArrayList<String> connectedClients;
    private static ArrayList<Boolean> clientInChat;
    private static ArrayList<SecretKeySpec> clientKeys;
    private static ArrayList<Socket> clientSockets;
    private static int sessionID;
    private int rand_cookie,port;
    private SecretKeySpec CK_A;
    private String userID;

    public TCPhandler() throws IOException {
        this.connectedClients = new ArrayList<String>();
        this.clientInChat = new ArrayList<Boolean>();
        this.clientKeys = new ArrayList<SecretKeySpec>();
        this.clientSockets = new ArrayList<Socket>( );
        this.clientSession = new ArrayList<Integer>();
        this.sessionID = 0;
    }

    public TCPhandler(int rand_cookie, int port, SecretKeySpec CK_A, String userID){
        this.rand_cookie = rand_cookie;
        this.userID = userID;
        this.port = port;
        this.CK_A = CK_A;
        clientKeys.add(CK_A);
        connectedClients.add(userID);
        clientInChat.add(false);
        clientSession.add(-1);
    }

    public void run(){
        try {
            ServerSocket TCPconn = new ServerSocket(port);
            Socket in = TCPconn.accept();
            clientSockets.add(in);

            DataInputStream inbound = new DataInputStream(in.getInputStream());
            DataOutputStream outbound = new DataOutputStream(in.getOutputStream());

            String received;
            String sending;

            while(true){
                received = UDPServer.decrypt(CK_A,inbound.readUTF().getBytes("UTF-8"));
                System.out.println(received);
                if(received.equals("CONNECT(" + rand_cookie + ")")) {
                    sending = "CONNECTED";
                    sending = new String(UDPServer.encrypt(CK_A, sending), StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                }

                if(received.equals("Log off")) {
                    sending = new String(UDPServer.encrypt(CK_A,"EXIT()"),StandardCharsets.US_ASCII);
                    outbound.writeUTF(sending);
                    in.close();
                    outbound.close();
                    TCPconn.close();
                    ///// remove the users info from all the Array lists /////
                    int index = connectedClients.indexOf(this.userID);
                    clientKeys.remove(index);
                    connectedClients.remove(index);
                    clientInChat.remove(index);
                    clientSession.remove(index);
                    clientSockets.remove(index);
                    break;
                }

                if(received.contains("CHAT(")){
                    String message = received.substring(received.indexOf(",")+1,received.length()-1);
                    int index = connectedClients.indexOf(this.userID);
                    int session = clientSession.get(index);

                        int idx = clientSession.indexOf(session);
                        if(idx != index){
                            index = idx;
                        }
                        else{
                            index = clientSession.lastIndexOf(session);
                        }

                    DataOutputStream temp = new DataOutputStream(clientSockets.get(index).getOutputStream());
                    sending = new String(UDPServer.encrypt(clientKeys.get(index),message),StandardCharsets.US_ASCII);
                    temp.writeUTF(sending);
                }

                if(received.contains("CHAT_REQUEST(")){
                    initiateChat(received,outbound);
                }

                if(received.contains("END_REQUEST(")){
                    int index = connectedClients.indexOf(this.userID);
                    int session = clientSession.get(index);
                    clientInChat.set(index,false);
                    clientSession.set(index,-1);
                    index = clientSession.indexOf(session);
                    DataOutputStream temp = new DataOutputStream(clientSockets.get(index).getOutputStream());
                    sending = "END_NOTIF(" + clientSession.get(index) + ")";
                    sending = new String(UDPServer.encrypt(clientKeys.get(index),sending),StandardCharsets.US_ASCII);
                    temp.writeUTF(sending);
                    clientInChat.set(index,false);
                    clientSession.set(index,-1);
                }

            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initiateChat(String received, DataOutputStream outbound) throws Exception {
        String sending;
        String checkIfConnected = received.substring(23,received.length()-1);
        int index;
        if(connectedClients.contains(checkIfConnected)){
            index = connectedClients.indexOf(checkIfConnected);
            if(clientInChat.get(index) == false) {
                sending = "CHAT_STARTED("+ ++sessionID + "," + checkIfConnected + ")";
                sending = new String(UDPServer.encrypt(CK_A,sending),StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
                DataOutputStream temp = new DataOutputStream(clientSockets.get(index).getOutputStream());
                sending = "CHAT_STARTED(" + sessionID + "," + this.userID + ")";
                sending = new String(UDPServer.encrypt(clientKeys.get(index),sending),StandardCharsets.US_ASCII);
                temp.writeUTF(sending);

                // sets the chatting sessionID and boolean for inChat
                clientInChat.set(index,true);
                clientSession.set(index,sessionID);
                clientInChat.set(connectedClients.indexOf(this.userID),true);
                clientSession.set(connectedClients.indexOf(this.userID),sessionID);
            }
            else{
                sending = "UNREACHABLE(" + checkIfConnected + ")";
                sending = new String(UDPServer.encrypt(CK_A, sending), StandardCharsets.US_ASCII);
                outbound.writeUTF(sending);
            }
        }
        else{
            sending = sending = "UNREACHABLE(" + checkIfConnected + ")";
            sending = new String(UDPServer.encrypt(CK_A,sending),
                    StandardCharsets.US_ASCII);
            outbound.writeUTF(sending);
        }
    }

}
