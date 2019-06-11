package ru.geographer29;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    private final static Logger logger = Logger.getLogger(Client.class);
    private final static String IP = "localhost";
    private final static int PORT = 8080;

    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    static {
        BasicConfigurator.configure();
    }

    public void run() {
        try {
            socket = new Socket(IP, PORT);
            logger.info("Connecting to " + IP + ":" + PORT);

            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            Scanner scanner = new Scanner(System.in);
            String msgSend = "";
            String msgReceive = "";


            do {
                try {
                    msgReceive = (String)in.readObject();

                    if (!msgReceive.equals("")) {
                        System.out.println("Server> " + msgReceive);
                    }

                    System.out.println("Enter a message: ");
                    msgSend = scanner.nextLine();
                    sendMsg(msgSend);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                    logger.error("Format has not recognized");
                }

            } while (!msgSend.equals("/quit"));

            logger.info("Client disconnected from server " + socket.getInetAddress().getHostAddress());

        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to connect to " + IP + ":" + PORT);
        } finally {
            try {
                in.close();
                out.close();
                socket.close();
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
            System.out.println("Client> " + msg);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to send message");
        }
    }

}
