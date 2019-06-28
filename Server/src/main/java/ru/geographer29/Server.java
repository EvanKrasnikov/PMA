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
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
    private PublicKey myPublicKey;
    private PrivateKey privateKey;
    private PrivateKey myPrivateKey;
    private SecretKey secretKey;

    private String msgSend = "";
    private String json = "";
    private Message message = null;

    private Response<Object> oResponse;
    private Response<RSAPublicKeyImpl> pkResponse;
    private Response<String> scResponse;
    private Response<Message> mResponse;
    private Response<String> enResponse;
    private TypeToken<Response<Object>> oToken = new TypeToken<Response<Object>>(){};
    private TypeToken<Response<RSAPublicKeyImpl>> pkToken = new TypeToken<Response<RSAPublicKeyImpl>>(){};
    private TypeToken<Response<Message>> mToken = new TypeToken<Response<Message>>(){};
    private TypeToken<Response<String>> enToken = new TypeToken<Response<String>>(){};

    {
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
        Cryptography.initialize(secretKey);

        for(;;) {
            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                //e.printStackTrace();
                //logger.error("Unable to receive object");
            }

            enResponse = gson.fromJson(json, enToken.getType());

            if (enResponse.getType() == Type.ENCRYPTED) {
                logger.info("Received json = " + json);
                json = Cryptography.decodeAndDecrypt(enResponse.getContent());

                mResponse = gson.fromJson(json, mToken.getType());
                message = mResponse.getContent();

                if (message.getBody().equals("/quit")) {
                    break;
                }

                logger.info(message.getSource() + "> " + message.getBody());

                msgSend = "Echo + " + message.getBody();
                message = new Message.Builder()
                        .setBody(msgSend)
                        .build();
                json = gson.toJson(message);
                msgSend = Cryptography.encryptAndEncode(json);

                enResponse = ResponseFactory.createEncryptedMessageResponse(msgSend);
                json = gson.toJson(enResponse);

                //logger.info("Sending json = " + json);

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
            //KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            //pairGenerator.initialize(4096);
            //KeyPair pair = pairGenerator.generateKeyPair();
            //myPrivateKey = pair.getPrivate();
            //myPublicKey = pair.getPublic();

            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Unable to generate keys");
        }
    }

    private void initCryptography() {
        try {
            for(;;) {
                json = (String)in.readObject();
                oResponse = new Gson().fromJson(json, oToken.getType());

                if (oResponse.getType() == Type.PUBLIC_KEY) {
                    pkResponse = gson.fromJson(json, pkToken.getType());
                    publicKey = pkResponse.getContent();
                    logger.info("Public key was accepted");

                    json = gson.toJson(ResponseFactory.createPublicKeyAcceptResponse());
                    out.writeObject(json);
                    logger.info("Sending accepting confirmation");
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized ");
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            if (cipher == null)
                throw new NullPointerException();

            try(CipherOutputStream cipherOutputStream = new CipherOutputStream(out, cipher)){

                logger.info("Sending secret key");
                //cipherOutputStream.write(mapper.writeValueAsBytes(ResponseFactory.createSecretKeyResponse(secretKey))); // check it

                String encodedSecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                json = gson.toJson(ResponseFactory.createSecretKeyResponse(encodedSecretKey));
                System.out.println(json);
                out.writeObject(json);

                for(;;) {

                    System.out.println("before receive");
                    json = (String)in.readObject();

                    System.out.println("after receive");

                    oResponse = new Gson().fromJson(json, oToken.getType());

                    if (oResponse.getType() == Type.SECRET_KEY_ACCEPT) {
                        logger.info("Secret key was accepted");
                        break;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to send or receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized ");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            logger.error("Unable to initialize cryptography");
        }

    }

}
