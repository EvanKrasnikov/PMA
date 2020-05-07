package ru.geographer29.cryptography;

public class KeyPair {

    private final String privateKey;
    private final String publicKey;

    KeyPair(String privateKey, String publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

}
