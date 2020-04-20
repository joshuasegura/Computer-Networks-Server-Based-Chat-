# Computer Networks Server Based Chat
COMPILE
javac Client.java
javac Server.java -cp gson-2.8.0.jar
RUN
java Client
java -cp gson-2.8.0.jar:. Server

Implemented chat history into the project. You have to link the .jar file in order to compile the Server.java now though because I used an external json library. I need to fix the session portion so that the sessions increment whenever the
Server.java file is reran. Just need to incorporate the timeout portion and the project should be done. -- JS

The TCP chat works now(log in, log out, chat). It can do multiple chats as well. Need to implement the chat history portion
    -- JS

I updated UDPClient.java and UDPServer.java and now the UDP authentication is done. Encryption done. TCP chat startup also done, this includes initiation and the actual chatting between clients. -- JS
