import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
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
        Random random = new Random();
        int rand = 0, index = 0;
        String in,out = null;
        InetAddress client_Address = null;
        int client_port;
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
                String validate_user = in.substring(6,end-1);
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
                    int rand_cookie = random.nextInt();
                    // still need to assign the port
                    byte[] encrypted = encrypt(CK_A, "AUTH_SUCCESS(rand_cookie)");
                    received = new byte[encrypted.length];
                    received = encrypted;
                    String test = decrypt(CK_A, received);
                    skip = true;
                    //decrypt(CK_A,received);
                }
                else
                    out = "AUTH_FAIL";
            }

            if(in.contains("bye"))
                break;

            if(skip == false){
                //System.out.println(out);
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
}
