package ru.geographer29.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.log4j.Logger;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

public abstract class AbstractServer implements Runnable {

    private final static Logger logger = Logger.getLogger(AbstractServer.class);
    protected final static int PORT = 8080;

    protected Socket socket;
    //protected ServerSocket serverSocket;

    protected ObjectOutputStream out;
    protected ObjectInputStream in;

    protected final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm").create();

    protected String msgSend = "";
    protected String json = "";
    protected Message message = null;

    protected Response response;

    public AbstractServer(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            logger.info("Client connected " + socket.getInetAddress().getHostAddress());

            initCryptography();
            mainLoop();

            logger.info("Client disconnected " + socket.getInetAddress().getHostAddress());

            TimeUnit.SECONDS.sleep(1);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e){
            e.printStackTrace();
        }finally {
            try {
                in.close();
                out.close();
                socket.close();
                //serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Unable to close streams and sockets");
            }
        }
    }

    abstract void initCryptography();
    abstract void mainLoop();

}
