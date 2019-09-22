package ru.geographer29;

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

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
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

    private SecretKey secretKey;
    private PublicKey publicKey;
    private PrivateKey privateKey;

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
        logger.debug("Starting main loop");

        for(;;) {
            System.out.println("Enter a message: ");
            msgSend = scanner.nextLine();
            logger.debug("Original message = " + msgSend);
            message = new Message.Builder()
                    .setBody(msgSend)
                    .setSource(IP)
                    .build();
            json = gson.toJson(ResponseFactory.createMessageResponse(message));
            logger.debug("Original json = " + json);
            json = Cryptography.encryptAndEncode(json);
            logger.debug("Encrypted message = " + json);
            json = gson.toJson(ResponseFactory.createEncryptedMessageResponse(json));
            logger.debug("Encrypted message json = " + json);

            try {
                out.writeObject(json);
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Unable to write object");
            }

            if (msgSend.equals("/quit"))
                break;

            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                logger.error("Unable to receive object");
            }

            logger.debug("Received json " + json);
            oResponse = gson.fromJson(json, oToken.getType());

            if (oResponse.getType() == Type.ENCRYPTED){
                enResponse = gson.fromJson(json, enToken.getType());
                json = Cryptography.decodeAndDecrypt(enResponse.getContent());

                logger.debug("Decrypted json " + json);
                mResponse = gson.fromJson(json, mToken.getType());
                message = mResponse.getContent();
                logger.debug("Message = " + message.getBody() );

                if (message.getBody() != null) {
                    System.out.println(message.getSource() + "> " + message.getBody());
                }
            }
        }

        logger.info("Client disconnected from server " + socket.getInetAddress().getHostAddress());
    }

    /**
     * Generating public and private key pair
     */

    private void generateKeys() {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            pairGenerator.initialize(4096);
            KeyPair pair = pairGenerator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();

            logger.debug("RSA keys were generated successfully");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Unable to generate keys");
        }
    }

    private void initCryptography() {
        try {
            /**
             * Sending pulic key to the server
             */

            String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            json = gson.toJson(ResponseFactory.createPublicKeyResponse(encoded));
            out.writeObject(json);

            for(;;) {
                json = (String)in.readObject();
                oResponse = gson.fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.PUBLIC_KEY_ACCEPT) {
                    logger.debug("Public key was accepted by server");
                    break;
                } else {
                    json = gson.toJson(ResponseFactory.createPublicKeyResponse(publicKey));
                    out.writeObject(json);
                }
            }

            /**
             * Setting up cryptography for secret key decryption
             */

            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                e.printStackTrace();
                logger.error("Unable to initialize cipher");
            }

            /**
             * Receiving and decrypting of secret key
             */

            for (;;) {
                json = (String) in.readObject();
                oResponse = gson.fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.SECRET_KEY) {
                    skResponse = gson.fromJson(json, skToken.getType());
                    String encoredSecretKey = skResponse.getContent();
                    byte[] decodedSecretKey = Base64.getDecoder().decode(encoredSecretKey);
                    byte[] decryptedSecretKey = cipher.doFinal(decodedSecretKey);
                    secretKey = new SecretKeySpec(decryptedSecretKey, 0, decryptedSecretKey.length, "AES");

                    logger.debug("Received json = " + json);
                    json = gson.toJson(ResponseFactory.createSecretKeyAcceptResponse());
                    out.writeObject(json);

                    logger.debug("Secret key accepted");
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to send or receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            logger.error("Can't decrypt public key");
        }

        Cryptography.initialize(secretKey);
        logger.debug("Cryptography initialized");
    }

}
