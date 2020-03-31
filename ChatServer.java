public static void main(String[] args) {
    int portNumber = 4444;
    serverSocket = null;
    try {
        ServerSocket serverSocket = new ServerSocket(portNumber);
    } catch (IOException e) {
        System.err.println("Could not listen on port: " + portNumber);
        System.exit(1);
    }


}

public static void acceptsClients() {
    while (true) {
        try {
            Socket socket = serverSocket.accept();
            ClientThread client = new ClientThread(socket);
            Thread thread = new Thread(client);
            thread.start();
            clients.add(client);
        } catch (IOException e) {
            System.out.println("Accept failed on: "+portNumber);
        }
    }
}