package ru.geographer29;

import org.apache.log4j.xml.DOMConfigurator;
import ru.geographer29.client.CustomCryptographyClient;

import java.io.File;

public class ClientLauncher {

    static {
        DOMConfigurator.configure(System.getProperty("user.dir") + File.separator + "log4j_clt.xml");
    }

    public static void main(String[] args) {

        CustomCryptographyClient client = new CustomCryptographyClient(
                "Timon"
        );

        client.run();

    }

}
