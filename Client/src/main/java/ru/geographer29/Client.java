package ru.geographer29;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import ru.geographer29.cryptography.Cryptography;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.ResponseFactory;
import ru.geographer29.responses.Type;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    private final static Logger logger = Logger.getLogger(Client.class);
    private final static String IP = "localhost";
    private final static int PORT = 8080;

    private Socket socket;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    private final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm").create();

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private SecretKey secretKey;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;

    private String msgSend = "";
    private String json = "";
    private Message message = null;
    private Response response = null;

    private Response<Object> oResponse;
    private Response<RSAPublicKeyImpl> pkResponse;
    private Response<String> skResponse;
    private Response<Message> mResponse;
    private Response<String> enResponse;
    private TypeToken<Response<Object>> oToken = new TypeToken<Response<Object>>(){};
    private TypeToken<Response<RSAPublicKeyImpl>> pkToken = new TypeToken<Response<RSAPublicKeyImpl>>(){};
    private TypeToken<Response<String>> skToken = new TypeToken<Response<String>>(){};
    private TypeToken<Response<Message>> mToken = new TypeToken<Response<Message>>(){};
    private TypeToken<Response<String>> enToken = new TypeToken<Response<String>>(){};

    {
        BasicConfigurator.configure();
    }

    public void run() {
        try {
            socket = new Socket(IP, PORT);
            logger.info("Connecting to " + IP + ":" + PORT);

            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            generateKeys();
            initCryptography();
            mainLoop();
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

    private void mainLoop() {
        Scanner scanner = new Scanner(System.in);
        Cryptography.initialize(secretKey);

        do {
            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                logger.error("Unable to receive object");
            }

            logger.info("Received json " + json);
            enResponse = gson.fromJson(json, enToken.getType());

            if (enResponse.getType() == Type.ENCRYPTED){
                json = Cryptography.decodeAndDecrypt(enResponse.getContent());

                mResponse = gson.fromJson(json, mToken.getType());
                message = mResponse.getContent();
                System.out.println(message.getBody());

                if (message.getBody() != null) {
                    System.out.println(message.getSource() + "> " + message.getBody());
                }
            }

            System.out.println("Enter a message: ");
            msgSend = scanner.nextLine();
            logger.info("Original message = " + msgSend);
            message = new Message.Builder()
                    .setBody(msgSend)
                    .build();
            json = gson.toJson(message);
            json = Cryptography.encryptAndEncode(json);
            logger.info("Encrypted message = " + json);
            json = gson.toJson(ResponseFactory.createEncryptedMessageResponse(json));
            logger.info("Encrypted message json =" + json);

            try {
                out.writeObject(json);
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Unable to write object");
            }
        } while (!msgSend.equals("/quit"));

        logger.info("Client disconnected from server " + socket.getInetAddress().getHostAddress());
    }

    private void generateKeys() {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            pairGenerator.initialize(4096);
            KeyPair pair = pairGenerator.generateKeyPair();
            myPrivateKey = pair.getPrivate();
            myPublicKey = pair.getPublic();

            //KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            //secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Unable to generate keys");
        }
    }

    private void initCryptography() {
        try {
            json = gson.toJson(ResponseFactory.createPublicKeyResponse(myPublicKey));
            out.writeObject(json);

            for(;;) {
                json = (String)in.readObject();

                oResponse = gson.fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.PUBLIC_KEY_ACCEPT) {
                    logger.info("Public key accepted");
                    break;
                } else {
                    json = gson.toJson(ResponseFactory.createPublicKeyResponse(myPublicKey));
                    out.writeObject(json);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to send or receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized");
        }

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            logger.error("Unable to initialize cipher");
        }

        try (
                CipherInputStream cipherInputStream = new CipherInputStream(in, cipher);
                InputStreamReader ir = new InputStreamReader(cipherInputStream);
                BufferedReader reader = new BufferedReader(ir)
        ){
            for (;;) {
                json = (String) in.readObject();
                oResponse = gson.fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.SECRET_KEY) {
                    skResponse = gson.fromJson(json, skToken.getType());
                    String encoredSecretKey = skResponse.getContent();
                    byte[] decodedSecretKey = Base64.getDecoder().decode(encoredSecretKey);
                    secretKey = new SecretKeySpec(decodedSecretKey, 0, decodedSecretKey.length, "DES");
                    logger.info("Received json =" + json);

                    json = gson.toJson(ResponseFactory.createSecretKeyAcceptResponse());
                    out.writeObject(json);

                    logger.info("Secret key accepted");
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to send or receive message");
        } catch (ClassNotFoundException e){
            e.printStackTrace();
        }

        logger.info("Cryptography initialized");
    }

}
