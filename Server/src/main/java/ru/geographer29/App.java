package ru.geographer29;

import org.apache.log4j.xml.DOMConfigurator;

import java.io.File;

public class App {

    static {
        DOMConfigurator.configure(System.getProperty("user.dir") + File.separator + "log4j_srv.xml");
    }

    public static void main( String[] args ) {

        AbstractServer server = new CustomCryptographyServer();
        server.run();

    }

}
