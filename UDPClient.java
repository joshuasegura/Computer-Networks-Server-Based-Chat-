import java.net.*;
import java.util.Scanner;
import java.io.IOException;

public class UDPClient {

    public static void main(String[] args) throws Exception{
	/**** This is the UDP client code ****/

	    Scanner input = new Scanner(System.in);

	    // create the datagram socket
        DatagramSocket d = new DatagramSocket();
        InetAddress ip = InetAddress.getLocalHost();
        byte buff[] = null;

        while(true){
            String in = input.nextLine();

            // convert the string into a byte array so that it can be sent
            buff = in.getBytes();

            // creates the datagram packet that will be sent to the server
            DatagramPacket DPSend = new DatagramPacket(buff, buff.length, ip, 12000);

            // sends the actual datagram
            d.send(DPSend);

            if(in.trim().equals("bye"))
                break;
        }
        System.out.println("out of client loop");
    }
}
