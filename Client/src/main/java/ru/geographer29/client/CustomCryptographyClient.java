package ru.geographer29.client;

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

    private String name;
    private String target;

    AES aes = new AES(AES.Mode.ECB);
    String iv = "0000000000000000";

    public CustomCryptographyClient(String name, String target) {
        this.name = name;
        this.target = target;
    }

    @Override
    void inputLoop() {
        logger.debug("Started input client thread");

        for(;;){
            if (msgSend.equals("/quit"))
                break;

            json = tryReceive();
            if (json.equals(""))
                continue;

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED){
                String decoded = new String(Base64.getDecoder().decode(response.getContent()));
                String decrypted = aes.decrypt(decoded, iv, secretKey);
                message = gson.fromJson(decrypted, Message.class);

                logger.debug("Receiving encrypted json = " + json);
                logger.debug("Receiving encoded message = " + response.getContent());
                logger.debug("Receiving encrypted message = " + decoded);
                logger.debug("Receiving original message json = " + decrypted);

                response = gson.fromJson(decrypted, Response.class);
                if (response.getType() == Type.MESSAGE) {
                    message = gson.fromJson(response.getContent(), Message.class);

                    if (message.getTarget()!= null && message.getBody() != null) {
                        String report = String.format("%s > %s", message.getTarget(), message.getBody());
                        System.out.println(report);
                    }
                }
            }
        }
    }

    @Override
    void outputLoop() {
        logger.debug("Started output client thread");
        Scanner scanner = new Scanner(System.in);

        for(;;) {
            System.out.println("Enter a message: ");
            msgSend = scanner.nextLine();

            message = new Message.Builder()
                    .setBody(msgSend)
                    .setSource(name)
                    .setTarget(target)
                    .build();
            json = gson.toJson(message);
            json = gson.toJson(createMessageResponse(json));

            String encrypted = aes.encrypt(json, iv, secretKey);
            String encoded = Base64.getEncoder().encodeToString(encrypted.getBytes());
            json = gson.toJson(createEncryptedResponse(encoded));

            logger.debug("Sending original json = " + json);
            logger.debug("Sending encrypted message = " + encrypted);
            logger.debug("Sending encoded message = " + encoded);
            logger.debug("Sending encrypted message json = " + json);

            trySend(json);

            if (msgSend.equals("/quit"))
                break;
        }
    }

    /**
     * Initialize cryptography using protocol
     */
    void initCryptography() {
        // Generating public and private key pair
        KeyPair keyPair = RSA.generateKeyPair(1024);
        privateKey = keyPair.getPrivateKey();
        publicKey = keyPair.getPublicKey();

        // Sending public key to the server
        String encoded = Base64.getEncoder().encodeToString(publicKey.getBytes());
        for(;;) {
            json = gson.toJson(createPublicKeyResponse(encoded));
            trySend(json);

            json = tryReceive();
            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.PUBLIC_KEY_ACCEPT) {
                logger.debug("Public key was accepted by server");
                break;
            }
        }

        // Receiving and decrypting of secret key
        for (;;) {
            json = tryReceive();
            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.SECRET_KEY) {
                RSA rsa = new RSA();
                String encodedSecretKey = response.getContent();
                byte[] decodedSecretKey = Base64.getDecoder().decode(encodedSecretKey);
                byte[] decryptedSecretKey = rsa.decrypt(decodedSecretKey, privateKey);
                secretKey = new String(decryptedSecretKey);

                logger.debug("Received secret key = " + secretKey);
                json = gson.toJson(createSecretKeyAcceptResponse());
                trySend(json);

                logger.debug("Secret key accepted");
                break;
            }
        }

        logger.debug("Cryptography initialized");
    }

    private synchronized void trySend(String json) {
        try {
            out.writeObject(json);
        } catch (IOException e) {
            e.printStackTrace();
            //logger.error("Unable to send message", e);
        }
    }

    private synchronized String tryReceive(){
        try {
            return (String)in.readObject();
        } catch (IOException e) {
            e.printStackTrace();
            //logger.error("Unable to receive message", e);
        } catch (ClassNotFoundException e) {
            //e.printStackTrace();
            //logger.error("Unable to cast Object", e);
        }
        return "";
    }

}
