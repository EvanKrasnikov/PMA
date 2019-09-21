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
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Server {

    private final static Logger logger = Logger.getLogger(Server.class);
    private final static int PORT = 8080;

    private Socket socket;
    private ServerSocket serverSocket;

    private ObjectOutputStream out;
    private ObjectInputStream in;

    private final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm").create();

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey secretKey;

    private String msgSend = "";
    private String json = "";
    private Message message = null;

    private Response<Object> oResponse;
    private Response<String> pkResponse;
    private Response<String> scResponse;
    private Response<Message> mResponse;
    private Response<String> enResponse;
    private TypeToken<Response<Object>> oToken = new TypeToken<Response<Object>>(){};
    private TypeToken<Response<String>> pkToken = new TypeToken<Response<String>>(){};
    private TypeToken<Response<Message>> mToken = new TypeToken<Response<Message>>(){};
    private TypeToken<Response<String>> enToken = new TypeToken<Response<String>>(){};

    static {
        BasicConfigurator.configure();
    }

    public void run() {
        try {
            serverSocket = new ServerSocket(PORT);

            logger.info("Waiting for connection ");
            socket = serverSocket.accept();

            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();
            in = new ObjectInputStream(socket.getInputStream());

            logger.info("Client connected " + socket.getInetAddress().getHostAddress());

            generateKeys();
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
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
                logger.error("Unable to close streams and sockets");
            }
        }
    }

    private void mainLoop() {
        logger.debug("Starting main loop");

        for(;;) {
            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                logger.error("Unable to receive object");
            }

            oResponse = gson.fromJson(json, oToken.getType());

            if (oResponse.getType() == Type.ENCRYPTED) {
                enResponse = gson.fromJson(json, enToken.getType());
                logger.debug("Received json = " + json);
                json = Cryptography.decodeAndDecrypt(enResponse.getContent());
                logger.debug("Decrypted json = " + json);

                mResponse = gson.fromJson(json, mToken.getType());
                message = mResponse.getContent();

                if (message.getBody().equals("/quit")) {
                    break;
                }

                logger.info(message.getSource() + "> " + message.getBody());
                System.out.println(message.getSource() + "> " + message.getBody());

                msgSend = "Echo + " + message.getBody();
                message = new Message.Builder()
                        .setBody(msgSend)
                        .setSource("Server")
                        .build();
                json = gson.toJson(ResponseFactory.createMessageResponse(message));
                logger.debug("Sending message = " + json);
                msgSend = Cryptography.encryptAndEncode(json);

                enResponse = ResponseFactory.createEncryptedMessageResponse(msgSend);
                json = gson.toJson(enResponse);

                try {
                    out.writeObject(json);
                } catch (IOException e) {
                    e.printStackTrace();
                    logger.error("Unable to send message");
                }
            }
        }
    }

    private void generateKeys() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Unable to generate keys");
        }
    }

    private void initCryptography() {
        try {

            /**
             *  Sending response that public key is accepted
             */

            for(;;) {
                json = (String)in.readObject();
                oResponse = new Gson().fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.PUBLIC_KEY) {
                    pkResponse = gson.fromJson(json, pkToken.getType());

                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pkResponse.getContent().getBytes()));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    publicKey = keyFactory.generatePublic(keySpec);
                    logger.debug("Public key was accepted " + publicKey);

                    json = gson.toJson(ResponseFactory.createPublicKeyAcceptResponse());
                    out.writeObject(json);
                    logger.debug("Sending accepting confirmation " + json);
                    break;
                }

            }

            /**
             * Initialize RSA for sending secret key
             */

            //IvParameterSpec iv = new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0});
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            /**
             * Sending encrypted secret key to the client
             */
            String encodedSecretKey = "";
            logger.debug("Secret key = " + secretKey);
            logger.debug("Secret key = " + secretKey.toString());
            byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());
            //encodedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
            encodedSecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            json = gson.toJson(ResponseFactory.createSecretKeyResponse(encodedSecretKey));
            logger.debug("Sending encoded secret key " + json);
            out.writeObject(json);

            for(;;) {
                json = (String)in.readObject();
                oResponse = new Gson().fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.SECRET_KEY_ACCEPT) {
                    logger.debug("Secret key was accepted");
                    break;
                }
            }

            Cryptography.initialize(secretKey);
            logger.debug("Cryptography successfully initialized");

        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized ");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
            logger.error("Unable to initialize cryptography");
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            logger.error("Unable to encrypt secret key");
        }
    }

}
