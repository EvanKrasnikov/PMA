package ru.geographer29.cryptography;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MessageDigest {

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

}
