package ru.geographer29.server;

import org.apache.log4j.Logger;
import ru.geographer29.cryptography.AES;
import ru.geographer29.cryptography.MessageDigest;
import ru.geographer29.cryptography.RSA;
import ru.geographer29.responses.Message;
import ru.geographer29.responses.Response;
import ru.geographer29.responses.Type;

import java.io.IOException;
import java.net.Socket;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

import static ru.geographer29.responses.ResponseFactory.*;


public class CustomCryptographyServer extends AbstractServer {

    private final static Logger logger = Logger.getLogger(CustomCryptographyServer.class);
    private static ConcurrentHashMap<String, CustomCryptographyServer> clients = new ConcurrentHashMap<>();
    private String secretKey;
    private String privateKey;
    private String publicKey;

    public CustomCryptographyServer(Socket socket) {
        super(socket);
    }

    void mainLoop() {
        MessageDigest md = new MessageDigest(secretKey);
        AES aes = new AES(AES.Mode.ECB);
        String iv = "0000000000000000";
        logger.debug("Starting main loop");

        for(;;) {
            json = tryReceive();

            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.ENCRYPTED) {

                String expectedHmac = response.getHmac();
                String actualHmac = md.computeHmac(response.getContent());
                if (!expectedHmac.equals(actualHmac)) {
                    logger.debug("Message is corrupted. Hmac is wrong.");
                    continue;
                }
                logger.debug("Expected hmac = " + expectedHmac);
                logger.debug("Actual hmac = " + actualHmac);

                String decoded = new String(Base64.getDecoder().decode(response.getContent()));
                String decrypted = aes.decrypt(decoded, iv, secretKey);

                logger.debug("Receiving encrypted json = " + json);
                logger.debug("Receiving encoded message = " + response.getContent());
                logger.debug("Receiving encrypted message = " + decoded);
                logger.debug("Receiving original message json = " + decrypted);

                response = gson.fromJson(decrypted, Response.class);
                if (response.getType() == Type.MESSAGE){
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

                    String encrypted = aes.encrypt(json, iv, secretKey);
                    String encoded = Base64.getEncoder().encodeToString(encrypted.getBytes());
                    String hmac = md.computeHmac(encoded);
                    response = createEncryptedResponse(encoded, hmac);

                    logger.debug("Sending original json = " + json);
                    logger.debug("Sending encrypted message = " + encrypted);
                    logger.debug("Sending encoded message = " + encoded);
                    logger.debug("Sending encrypted message json = " + json);

                    json = gson.toJson(response);
                    trySend(json);
                }
            }
        }
    }

    // Initialize cryptography using protocol
    void initCryptography() {
        // Generate secret key
        secretKey = AES.generateSecretKey(128);
        logger.debug("Secret key = " + secretKey);

        // Sending response if public key is accepted
        for(;;) { ;
            json = tryReceive();
            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.PUBLIC_KEY) {
                publicKey = new String(Base64.getDecoder().decode(response.getContent().getBytes()));
                logger.debug("Public key was accepted " + publicKey);
                json = gson.toJson(createPublicKeyAcceptResponse());
                trySend(json);
                logger.debug("Sending accepting confirmation " + json);
                break;
            }
        }

        // Preparing response and sending encrypted secret key to the client
        RSA rsa = new RSA();
        byte[] encryptedSecretKey = rsa.encrypt(secretKey.getBytes(), publicKey);
        String encodedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKey);
        json = gson.toJson(createSecretKeyResponse(encodedSecretKey));

        for(;;) {
            logger.debug("Sending secret key = " + secretKey);
            trySend(json);

            json = tryReceive();
            response = gson.fromJson(json, Response.class);
            if (response.getType() == Type.SECRET_KEY_ACCEPT) {
                logger.debug("Secret key was accepted");
                break;
            }
        }

        logger.debug("Cryptography successfully initialized");
    }

    private String tryReceive(){
        try {
            return (String)in.readObject();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to receive message");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            logger.error("Can not cast String");
        }
        return "";
    }

    private void trySend(String json){
        try {
            out.writeObject(json);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Unable to send message");
        }
    }

}
