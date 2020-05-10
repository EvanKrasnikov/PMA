package ru.geographer29;

import org.apache.log4j.Logger;
import ru.geographer29.cryptography.AES;
import ru.geographer29.cryptography.RSA;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.Type;

import java.io.IOException;
import java.util.Base64;

import static ru.geographer29.responses.ResponseFactory.*;


public class CustomCryptographyServer extends AbstractServer {

    private final static Logger logger = Logger.getLogger(CustomCryptographyServer.class);
    private String secretKey;
    private String privateKey;
    private String publicKey;

    void mainLoop() {
        AES aes = new AES(AES.Mode.ECB);
        String iv = "0000000000000000";
        logger.debug("Starting main loop");

        for(;;) {
            try {
                json = (String)in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                //logger.error("Unable to receive object");
            }

            logger.debug("Receiving encrypted message json = " + json);

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED) {
                //response = gson.fromJson(response.getContent(), Response.class);
                String decoded = new String(Base64.getDecoder().decode(response.getContent()));
                String decrypted = aes.decrypt(decoded, iv, secretKey);
                logger.debug("Receiving encoded message = " + response.getContent());
                logger.debug("Receiving encrypted message = " + decoded);
                logger.debug("Receiving original message json = " + decrypted);

                //message = gson.fromJson(decrypted, Message.class);
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
                String encrypted = aes.encrypt(json, iv, secretKey);
                String encoded = Base64.getEncoder().encodeToString(encrypted.getBytes());

                response = createEncryptedResponse(encoded);
                json = gson.toJson(response);

                try {
                    out.writeObject(json);
                } catch (IOException e) {
                    e.printStackTrace();
                    //logger.error("Unable to send message");
                }
            }
        }
    }

    /**
     * Generate secret key
     */
    void generateKeys() {
        secretKey = AES.generateSecretKey(128);
        if (secretKey.equals("")){
            logger.error("Secret key is empty");
        }
        logger.debug("Secret key = " + secretKey);
    }

    /**
     * Initialize cryptography using protocol
     */
    void initCryptography() {
        try {
            /**
             *  Sending response if public key is accepted
             */
            for(;;) {
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.PUBLIC_KEY) {
                    publicKey = new String(Base64.getDecoder().decode(response.getContent().getBytes()));
                    logger.debug("Public key was accepted " + publicKey);
                    json = gson.toJson(createPublicKeyAcceptResponse());
                    out.writeObject(json);
                    logger.debug("Sending accepting confirmation " + json);
                    break;
                }

            }

            /**
             * Preparing response and sending encrypted secret key to the client
             */
            RSA rsa = new RSA();
            byte[] encryptedSecretKey = rsa.encrypt(secretKey.getBytes(), publicKey);
            String encodedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
            json = gson.toJson(createSecretKeyResponse(encodedSecretKey));

            for(;;) {
                logger.debug("Sending secret key = " + secretKey);
                out.writeObject(json);
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.SECRET_KEY_ACCEPT) {
                    logger.debug("Secret key was accepted");
                    break;
                }
            }

            logger.debug("Cryptography successfully initialized");

        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Format has not recognized ");
        }
    }

}
