import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class UDPServer {

    private static DatagramSocket d;
    private static DatagramPacket DPreceived,DPsending;
    private static byte[] received;
    private static String real_user = "jas151530";
    private static String password = "password";
    private static String Xres;

    public static void main(String[] args) throws Exception{
        /**** This is the server for the chat system  ****/

        // new datagram socket at port 12000
        d = new DatagramSocket(12000);
        String in,out = null;
        InetAddress client_Address = null;
        int client_port;

        while(true){
            received = new byte[65535];
            DPreceived = new DatagramPacket(received, received.length);
            d.receive(DPreceived);
            client_Address = DPreceived.getAddress();
            client_port = DPreceived.getPort();
            in = new String(DPreceived.getData()).trim();
            if(in.contains("HELLO(")){
                int end = in.length();
                String validate_user = in.substring(6,end-1);
                if(validate_user.equals(real_user)){
                    Random random = new Random();
                    int rand = random.nextInt(); // generates the random number
                    Xres = A3(rand, password);
                    out = "CHALLENGE(" + rand + ")";
                }
                else
                    out = validate_user + " isn't a valid user";
            }
            else if(in.contains("RESPONSE(")){
                String res = in.substring(9,in.length()-1);
                if(res.equals(Xres) ){
                    out = "AUTH_SUCCESS(rand_cookie, port_number)";
                }
                else
                    out = "AUTH_FAIL";
            }

            if(in.contains("bye"))
                break;

            System.out.println(out);
            DPsending = new DatagramPacket(out.getBytes(),out.length(),client_Address,client_port);
            d.send(DPsending);
        }
        System.out.println("out of server loop");
    }

    // This is the authentication algorithm for the UDP user verification
    private static String A3(int rand, String password) throws NoSuchAlgorithmException {
        String hash = Integer.toString(rand) + password;
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
