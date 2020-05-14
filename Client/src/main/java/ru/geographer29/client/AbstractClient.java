package ru.geographer29.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.log4j.Logger;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public abstract class AbstractClient extends Thread {
    private final static Logger logger = Logger.getLogger(AbstractClient.class);
    protected final static String IP = "localhost";
    private final static int PORT = 8080;

    protected Socket socket;
    protected ObjectInputStream in;
    protected ObjectOutputStream out;

    protected final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm").create();

    protected String msgSend = "";
    protected String json = "";
    protected Message message = null;
    protected Response response;

    @Override
    public void run() {
        try {
            socket = new Socket(IP, PORT);
            logger.info("Connecting to " + IP + ":" + PORT);

            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            initCryptography();
            outputThread.start();


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

    protected Thread inputThread = new Thread(this::inputLoop);
    protected Thread outputThread = new Thread(this::outputLoop);

    abstract void initCryptography();
    abstract void inputLoop();
    abstract void outputLoop();

}
