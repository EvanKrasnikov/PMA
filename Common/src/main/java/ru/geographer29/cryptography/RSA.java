package ru.geographer29.cryptography;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private final static BigInteger one = BigInteger.ONE;
    private final static String DELIMITER = "#";
    private String privateKey;
    private String publicKey;

    public static KeyPair generateKeyPair(int keyLength) {
        SecureRandom rand = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(keyLength / 2, rand);
        BigInteger q = BigInteger.probablePrime(keyLength / 2, rand);
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));
        BigInteger e = BigInteger.probablePrime(keyLength / 2, rand);

        while (phi.gcd(e).compareTo(one) > 0 && e.compareTo(phi) < 0) {
            e = e.add(one);
        }

        BigInteger d = e.modInverse(phi);

        return new KeyPair(
                n.toString(16) + DELIMITER + d.toString(16),
                n.toString(16) + DELIMITER + e.toString(16)
        );
    }

    public byte[] encrypt(byte[] message, String publicKey) {
        String[] arr = publicKey.split(DELIMITER);
        BigInteger e = new BigInteger(arr[1], 16);
        BigInteger n = new BigInteger(arr[0], 16);

        return (new BigInteger(message)).modPow(e, n).toByteArray();
    }

    public byte[] decrypt(byte[] encMessage, String privateKey) {
        String[] arr = privateKey.split(DELIMITER);
        BigInteger d = new BigInteger(arr[1], 16);
        BigInteger n = new BigInteger(arr[0], 16);

        return (new BigInteger(encMessage)).modPow(d, n).toByteArray();
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

}
