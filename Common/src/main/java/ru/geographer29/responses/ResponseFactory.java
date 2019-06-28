package ru.geographer29.responses;

import sun.security.rsa.RSAPublicKeyImpl;

import javax.crypto.SecretKey;
import java.security.PublicKey;
//import com.sun.crypto.provider.Des;

public class ResponseFactory {

    public static Response<Message> createMessageResponse(Object content) {
        return new Response.Builder<Message>()
                .setType(Type.MESSAGE)
                .setContent(content)
                .build();
    }

    public static Response<RSAPublicKeyImpl> createPublicKeyResponse(Object content) {
        return new Response.Builder<RSAPublicKeyImpl>()
                .setType(Type.PUBLIC_KEY)
                .setContent(content)
                .build();
    }

    public static Response<Object> createPublicKeyAcceptResponse() {
        return new Response.Builder<Object>()
                .setType(Type.PUBLIC_KEY_ACCEPT)
                .build();
    }

    public static Response<String> createSecretKeyResponse(Object content) {
        return new Response.Builder<String>()
                .setType(Type.SECRET_KEY)
                .setContent(content)
                .build();
    }

    public static Response<Object> createSecretKeyAcceptResponse() {
        return new Response.Builder<Object>()
                .setType(Type.SECRET_KEY_ACCEPT)
                .build();
    }

    public static Response<String> createEncryptedMessageResponse(Object content){
        return new Response.Builder<String>()
                .setType(Type.ENCRYPTED)
                .setContent(content)
                .build();
    }

}
