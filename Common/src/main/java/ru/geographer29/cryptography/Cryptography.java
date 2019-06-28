package ru.geographer29.cryptography;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Cryptography {

    private final static Logger logger = Logger.getLogger(Cryptography.class);
    private static Cipher eCipher;
    private static Cipher dCipher;

    private Cryptography(){}

    static {
        BasicConfigurator.configure();
    }

    public static Cryptography initialize(SecretKey secretKey) {
        try {
            eCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            eCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            dCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            dCipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return new Cryptography();
    }

    public static byte[] encrypt(byte[] bytes) {
        try {
            return eCipher.doFinal(bytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            logger.error("Unable to encrypt");
        }
        return null;
    }

    public static byte[] decrypt(byte[] bytes) {
        try {
            return dCipher.doFinal(bytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            logger.error("Unable to decrypt");
        }
        return null;
    }

    public static String encodeToBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decodeFromBase64 (byte[] bytes){
        return Base64.getDecoder().decode(bytes);
    }

    public static String encryptAndEncode(String data) {
        byte[] encrypted = encrypt(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decodeAndDecrypt(String data) {
        byte[] decoded = Base64.getDecoder().decode(data);
        byte[] decrypted = decrypt(decoded);
        return new String(decrypted);
    }

}
