package ru.geographer29;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private final static Logger logger = Logger.getLogger(Server.class);
    private final static int PORT = 8080;

    private Socket socket;
    private ServerSocket serverSocket;
    private ObjectOutputStream out;
    private ObjectInputStream in;

    static {
        BasicConfigurator.configure();
    }

    public void run() {
        try {
            serverSocket = new ServerSocket(PORT);

            System.out.println("Waiting for connection ");
            socket = serverSocket.accept();

            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            logger.info("Client connected " + socket.getInetAddress().getHostAddress());

            if (socket.isConnected())
                sendMsg("Connection successful");

            String msg = "";

            do {
                try {
                    msg  = (String)in.readObject();
                    System.out.println("Client> " + msg);

                    sendMsg("echo + " + msg);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                    logger.error("Format is not recognized");
                }
            } while (!msg.equals("/quit"));

            logger.info("Client disconnected " + socket.getInetAddress().getHostAddress());

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
                out.close();
                socket.close();
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Unable to close streams and sockets");
            }
        }
    }

    private void sendMsg(Object msg) {
        try {
            out.writeObject(msg);
            out.flush();
            System.out.println("Server> " + msg);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to send message");
        }
    }

}
