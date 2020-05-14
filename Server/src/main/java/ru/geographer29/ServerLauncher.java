package ru.geographer29;

import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import ru.geographer29.server.CustomCryptographyServer;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerLauncher {

    static {
        DOMConfigurator.configure(System.getProperty("user.dir") + File.separator + "log4j_srv.xml");
    }

    private final static Logger logger = Logger.getLogger(ServerLauncher.class);

    public static void main(String[] args) {
        //ServerSocket serverSocket = null;
        int port = 8080;

        try {
            ServerSocket serverSocket  = new ServerSocket(port);

            logger.info("Waiting for connection ");

            while (true){
                Socket socket = serverSocket.accept();
                Thread t = new Thread(new CustomCryptographyServer(socket));
                t.start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
