import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;
import java.io.IOException;


public class UDPClient {

    private static DatagramSocket d;
    private static DatagramPacket DPreceived, DPsending;
    private static byte[] received;
    private static String clientID = "jas151530";
    private static String password = "password1";


    public static void main(String[] args) throws Exception{
        /**** This is the UDP client code ****/

        Scanner input = new Scanner(System.in);

        // create the datagram socket
        DatagramSocket d = new DatagramSocket();
        InetAddress ip = InetAddress.getLocalHost();
        String in, out;

        System.out.println("This is just to get the UDP authentication working just type 'Log on' \n\tand" +
                " follow the steps from there, the password for now is just password" );
        out = input.nextLine();

        while(true){
            if(!out.equals("bye")){
                if (out.equals("Log on")) {
                    out = "HELLO(" + clientID + ")";
                }

                // sends the packet to the server
                DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12001);
                d.send(DPsending);

                // buffer for data sent by the server
                received = new byte[65535];
                DPreceived = new DatagramPacket(received,received.length);
                d.receive(DPreceived);
                in = new String(DPreceived.getData()).trim();
                if(in.contains("CHALLENGE(")){
                    int end = in.length();
                    String rand = in.substring(10,end-1);
                    String res = A3(rand, password);
                    out = "RESPONSE(" + res + ")";
                    DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12001);
                    d.send(DPsending);
                }
                if(in.contains("AUTH_FAIL")){
                    System.out.println("Incorrect password .... exiting");
                    break;
                }
                if(in.contains("AUTH_SUCCESS(")){
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

    private static String A3(String rand, String password) throws NoSuchAlgorithmException {
        String hash = rand + password;
        System.out.println("Hashing: " + hash);
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

}

