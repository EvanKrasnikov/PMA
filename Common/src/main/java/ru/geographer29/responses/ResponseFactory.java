package ru.geographer29.responses;

public class ResponseFactory {

    public static Response createMessageResponse(String content) {
        return new Response.Builder()
                .setType(Type.MESSAGE)
                .setContent(content)
                .build();
    }

    public static Response createPublicKeyResponse(String content) {
        return new Response.Builder()
                .setType(Type.PUBLIC_KEY)
                .setContent(content)
                .build();
    }

    public static Response createPublicKeyAcceptResponse() {
        return new Response.Builder()
                .setType(Type.PUBLIC_KEY_ACCEPT)
                .build();
    }

    public static Response createSecretKeyResponse(String content) {
        return new Response.Builder()
                .setType(Type.SECRET_KEY)
                .setContent(content)
                .build();
    }

    public static Response createSecretKeyAcceptResponse() {
        return new Response.Builder()
                .setType(Type.SECRET_KEY_ACCEPT)
                .build();
    }

    public static Response createEncryptedResponse(String content, String hmac){
        return new Response.Builder()
                .setType(Type.ENCRYPTED)
                .setContent(content)
                .setHmac(hmac)
                .build();
    }

}
