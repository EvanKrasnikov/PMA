package ru.geographer29.responses;

public class Response {

    private final Type type;
    private final String content;
    private final String hmac;

    private Response(Type type, String content, String hmac) {
        this.type = type;
        this.content = content;
        this.hmac = hmac;
    }

    public Type getType() {
        return type;
    }

    public String getContent() {
        return content;
    }

    public String getHmac() {
        return hmac;
    }

    static class Builder{

        private Type type;
        private String content;
        private String hmac;

        public Builder setType(Type type){
            this.type = type;
            return this;
        }

        public Builder setContent(String content){
            this.content = content;
            return this;
        }

        public Builder setHmac(String hmac){
            this.hmac = hmac;
            return this;
        }

        public Response build(){
            return new Response(type, content, hmac);
        }

    }

}
