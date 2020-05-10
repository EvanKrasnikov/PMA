package ru.geographer29;

import org.apache.log4j.Logger;
import ru.geographer29.cryptography.Cryptography;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.Type;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import static ru.geographer29.responses.ResponseFactory.*;

public class VanillaCryptographyClient extends AbstractClient {

    private final static Logger logger = Logger.getLogger(VanillaCryptographyClient.class);
    PublicKey publicKey;
    SecretKey secretKey;
    PrivateKey privateKey;

    void mainLoop() {
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
            json = gson.toJson(message);
            json = gson.toJson(createMessageResponse(json));
            logger.debug("Original json = " + json);
            json = Cryptography.encryptAndEncode(json);
            logger.debug("Encrypted message = " + json);
            json = gson.toJson(createEncryptedResponse(json));
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

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED){
                json = Cryptography.decodeAndDecrypt(response.getContent());
                logger.debug("Decrypted json " + json);
                message = gson.fromJson(response.getContent(), Message.class);
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

    void initCryptography() {
        try {
            /**
             * Sending public key to the server
             */

            String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            json = gson.toJson(createPublicKeyResponse(encoded));
            out.writeObject(json);

            for(;;) {
                json = (String)in.readObject();
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.PUBLIC_KEY_ACCEPT) {
                    logger.debug("Public key was accepted by server");
                    break;
                } else {
                    json = gson.toJson(publicKey);
                    json = gson.toJson(createPublicKeyResponse(json));
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
                response = gson.fromJson(json, Response.class);
                if (response.getType() == Type.SECRET_KEY) {
                    String encoredSecretKey = response.getContent();
                    byte[] decodedSecretKey = Base64.getDecoder().decode(encoredSecretKey);
                    byte[] decryptedSecretKey = cipher.doFinal(decodedSecretKey);
                    secretKey = new SecretKeySpec(decryptedSecretKey, 0, decryptedSecretKey.length, "AES");

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
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            logger.error("Can't decrypt public key");
        }

        Cryptography.initialize(secretKey);
        logger.debug("Cryptography initialized");
    }

}
