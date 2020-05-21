package ru.geographer29.server;

import org.apache.log4j.Logger;
import ru.geographer29.cryptography.Cryptography;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.Type;

import javax.crypto.*;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static ru.geographer29.responses.ResponseFactory.*;

public class VanillaCryptographyServer extends AbstractServer {

    private final static Logger logger = Logger.getLogger(VanillaCryptographyServer.class);
    private SecretKey secretKey;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public VanillaCryptographyServer(Socket socket) {
        super(socket);
    }

    void mainLoop() {
        logger.debug("Starting main loop");

        for(;;) {
            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                logger.error("Unable to receive object");
            }

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED) {
                response = gson.fromJson(json, Response.class);
                logger.debug("Received json = " + json);
                json = Cryptography.decodeAndDecrypt(response.getContent());
                logger.debug("Decrypted json = " + json);

                message = gson.fromJson(response.getContent(), Message.class);
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
                json = gson.toJson(message);
                json = gson.toJson(createMessageResponse(json));
                logger.debug("Sending message = " + json);
                msgSend = Cryptography.encryptAndEncode(json);

                response = createEncryptedResponse(msgSend, "");
                json = gson.toJson(response);

                try {
                    out.writeObject(json);
                } catch (IOException e) {
                    e.printStackTrace();
                    logger.error("Unable to send message");
                }
            }
        }
    }

    void generateKeys() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Unable to generate keys");
        }
    }

    void initCryptography() {
        try {

            /**
             *  Sending response that public key is accepted
             */

            for(;;) {
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.PUBLIC_KEY) {
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(response.getContent().getBytes()));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    publicKey = keyFactory.generatePublic(keySpec);
                    logger.debug("Public key was accepted " + publicKey);

                    json = gson.toJson(createPublicKeyAcceptResponse());
                    out.writeObject(json);
                    logger.debug("Sending accepting confirmation " + json);
                    break;
                }

            }

            /**
             * Initialize RSA for sending secret key
             */

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            /**
             * Sending encrypted secret key to the client
             */
            String encodedSecretKey = "";
            logger.debug("Secret key = " + secretKey);
            logger.debug("Secret key = " + secretKey.toString());
            byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());
            encodedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
            json = gson.toJson(createSecretKeyResponse(encodedSecretKey));

            for(;;) {
                logger.debug("Sending encoded secret key " + json);
                out.writeObject(json);
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.SECRET_KEY_ACCEPT) {
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
