package ru.geographer29.responses;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Response<T> {

    @JsonProperty("type")
    private final Type type;
    @JsonProperty("content")
    private final T content;

    @JsonCreator
    private Response(
            @JsonProperty("type") Type type,
            @JsonProperty("content") T content
    ) {
        this.type = type;
        this.content = content;
    }

    public Type getType() {
        return type;
    }

    public T getContent() {
        return content;
    }

    static class Builder<T>{

        private Type type;
        private T content;

        public Builder<T> setType(Type type){
            this.type = type;
            return this;
        }

        @SuppressWarnings("unchecked")
        public Builder<T> setContent(Object o){
            this.content = (T)o;
            return this;
        }

        public Response<T> build(){
            return new Response<>(type, content);
        }

    }

}
