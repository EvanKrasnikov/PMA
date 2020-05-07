package ru.geographer29;

import org.apache.log4j.Logger;
import ru.geographer29.cryptography.AES;
import ru.geographer29.cryptography.KeyPair;
import ru.geographer29.cryptography.RSA;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.Type;

import java.io.IOException;
import java.util.Base64;
import java.util.Scanner;

import static ru.geographer29.responses.ResponseFactory.*;

public class CustomCryptographyClient extends AbstractClient {

    private final static Logger logger = Logger.getLogger(CustomCryptographyClient.class);
    private String secretKey;
    private String publicKey;
    private String privateKey;

    void mainLoop() {
        Scanner scanner = new Scanner(System.in);
        AES aes = new AES(AES.Mode.ECB);
        String iv = "0000000000000000";
        logger.debug("Starting main loop");

        for(;;) {
            System.out.println("Enter a message: ");
            msgSend = scanner.nextLine();
            logger.debug("Original message = " + msgSend);
            message = new Message.Builder()
                    .setBody(msgSend)
                    .setSource(IP)
                    .build();
            json = gson.toJson(message);
            json = gson.toJson(createMessageResponse(json));
            logger.debug("Original json = " + json);
            String encrypted = aes.encrypt(json, iv, secretKey);
            String encoded = Base64.getEncoder().encodeToString(encrypted.getBytes());
            logger.debug("Encoded message = " + encrypted);
            json = gson.toJson(createEncryptedMessageResponse(encoded));
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

            logger.debug("Received json = " + json);

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED){
                byte[] decoded = Base64.getDecoder().decode(response.getContent());
                String decrypted = aes.encrypt(new String(decoded), iv, secretKey);
                logger.debug("Decrypted json = " + json);
                message = gson.fromJson(decrypted, Message.class);
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
    void generateKeys() {
        KeyPair keyPair = RSA.generateKeyPair(1024);
        if (keyPair == null) {
            logger.error("Public and private keys are not generated");
        }
        privateKey = keyPair.getPrivateKey();
        publicKey = keyPair.getPublicKey();
    }

    /**
     * Initialize cryptography using protocol
     */
    void initCryptography() {
        try {
            /**
             * Sending public key to the server
             */
            String encoded = Base64.getEncoder().encodeToString(publicKey.getBytes());

            for(;;) {
                json = gson.toJson(createPublicKeyResponse(encoded));
                out.writeObject(json);
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.PUBLIC_KEY_ACCEPT) {
                    logger.debug("Public key was accepted by server");
                    break;
                }
            }

            /**
             * Receiving and decrypting of secret key
             */
            for (;;) {
                json = (String) in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.SECRET_KEY) {
                    RSA rsa = new RSA();
                    String encodedSecretKey = response.getContent();
                    byte[] decodedSecretKey = Base64.getDecoder().decode(encodedSecretKey);
                    byte[] decryptedSecretKey = rsa.decrypt(decodedSecretKey, privateKey);
                    secretKey = new String(decryptedSecretKey);

                    logger.debug("Received json = " + json);
                    json = gson.toJson(createSecretKeyAcceptResponse());
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
        }

        logger.debug("Cryptography initialized");
    }

}
