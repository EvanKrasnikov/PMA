package ru.geographer29.cryptography;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MessageDigest {

    private final static Logger logger = Logger.getLogger(MessageDigest.class);
    private final String algorythm = "HmacSHA1";
    private Mac mac;

    public MessageDigest(String key) {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), algorythm);

        try {
            mac = Mac.getInstance(algorythm);
            mac.init(secretKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public String computeHmac(String message)  {
        byte[] macData = mac.doFinal(message.getBytes());
        byte[] hex = new Hex().encode(macData);
        String result = new String(hex);
        return result.toUpperCase();
    }

    public boolean checkDigest(String expectedHmac, String data) {
        String actualHmac = computeHmac(data);
        if (!expectedHmac.equals(actualHmac)) {
            logger.debug("Message is corrupted. Hmac is wrong.");
            logger.debug("Expected hmac = " + expectedHmac);
            logger.debug("Actual hmac = " + actualHmac);
            return false;
        }
        return true;
    }

}
