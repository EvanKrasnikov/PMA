package ru.geographer29;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import ru.geographer29.entities.Message;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;


public class Server {

    private final static Logger logger = Logger.getLogger(Server.class);
    private final static int PORT = 8080;

    private Socket socket;
    private ServerSocket serverSocket;

    private ObjectOutputStream out;
    private ObjectInputStream in;

    private String target = getClass().getName();
    private final DateFormat dateFormat = new SimpleDateFormat(("yyyy-MM-dd HH:mm"));

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
                sendMsg("Connection successful", target);

            String json = "";
            Message message = null;

            do {
                try {
                    json = (String)in.readObject();

                    ObjectMapper mapper = new ObjectMapper();
                    mapper.setDateFormat(dateFormat);
                    message = mapper.readValue(json, Message.class);

                    System.out.println(message.getSource() + "> " + message.getBody());
                    System.out.println("FULL JSON: " + json);

                    sendMsg("echo + " + message.getBody(), target);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                    logger.error("Format is not recognized");
                }
            } while (!message.getBody().equals("/quit"));

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
