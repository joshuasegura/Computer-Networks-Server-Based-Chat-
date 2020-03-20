import java.net.*;

public class UDPServer {

    public static void main(String[] args) throws Exception{
        /**** This is the server for the chat system  ****/

        // new datagram socket at port 12000
        DatagramSocket d = new DatagramSocket(12000);
        byte[] receive = new byte[65535]; // buffer to hold the incoming message

        DatagramPacket DpReceived = null;

        while(true){
            // creates a datagram packet that receives data
            DpReceived = new DatagramPacket(receive, receive.length);
            d.receive(DpReceived);

            String str = new String(receive);
            if(str.trim().equals("bye")){
                System.out.println("Client sent bye closing the connection");
                break;
            }
            else{
                System.out.println(str);
            }

            receive = new byte[65535];

        }
        System.out.println("out of server loop");
    }
}
