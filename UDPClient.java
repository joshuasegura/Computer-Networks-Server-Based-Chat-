import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.io.IOException;

public class UDPClient {

    private static DatagramSocket d;
    private static DatagramPacket DPreceived, DPsending;
    private static byte[] received;

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
                    out = "HELLO(jas151530)";
                }

                // sends the packet to the server
                DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12000);
                d.send(DPsending);

                // buffer for data sent by the server
                received = new byte[65535];
                DPreceived = new DatagramPacket(received,received.length);
                d.receive(DPreceived);
                in = new String(DPreceived.getData()).trim();
                if(in.contains("CHALLENGE(")){
                    int end = in.length();
                    System.out.println("Enter Password: ");
                    String password = input.nextLine();
                    String rand = in.substring(10,end-1);
                    String res = A3(rand, password);
                    out = "RESPONSE(" + res + ")";
                    DPsending = new DatagramPacket(out.getBytes(),out.length(),ip,12000);
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
}
