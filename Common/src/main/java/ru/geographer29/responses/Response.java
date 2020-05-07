package ru.geographer29.responses;

public class Response {

    private final Type type;
    private final String content;

    private Response(Type type, String content) {
        this.type = type;
        this.content = content;
    }

    public Type getType() {
        return type;
    }

    public String getContent() {
        return content;
    }

    static class Builder{

        private Type type;
        private String content;

        public Builder setType(Type type){
            this.type = type;
            return this;
        }

        public Builder setContent(String content){
            this.content = content;
            return this;
        }

        public Response build(){
            return new Response(type, content);
        }

    }

}
