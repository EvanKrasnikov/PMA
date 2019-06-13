package ru.geographer29;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import ru.geographer29.entities.Message;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

public class Client {
    private final static Logger logger = Logger.getLogger(Client.class);
    private final static String IP = "localhost";
    private final static int PORT = 8080;

    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    private String target = getClass().getName();
    private final DateFormat dateFormat = new SimpleDateFormat(("yyyy-MM-dd HH:mm"));


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
            String json = "";


            do {
                try {
                    json = (String)in.readObject();

                    ObjectMapper mapper = new ObjectMapper();
                    mapper.setDateFormat(dateFormat);
                    Message message = mapper.readValue(json, Message.class);

                    if (!message.getBody().equals("")) {
                        System.out.println(message.getSource() + "> " + message.getBody());
                    }

                    System.out.println("Enter a message: ");
                    msgSend = scanner.nextLine();
                    sendMsg(msgSend, target);
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

    private void sendMsg(String body, String target) {
        try {
            Message message = new Message();
            message.setBody(body);
            message.setTarget(target);
            message.setSource(getClass().getSimpleName());
            message.setTimestamp(new Date());

            ObjectMapper mapper = new ObjectMapper();
            mapper.setDateFormat(dateFormat);
            String json = mapper.writeValueAsString(message);

            out.writeObject(json);
            out.flush();
            System.out.println(getClass().getSimpleName() + "> " + body);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Failed to send message");
        }
    }

}
