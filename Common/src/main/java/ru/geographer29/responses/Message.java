package ru.geographer29.responses;

import java.util.Date;

public class Message {

    private String source;
    private String target;
    private String body;
    private Date timestamp;

    public String getSource() {
        return source;
    }

    public String getTarget() {
        return target;
    }

    public String getBody() {
        return body;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    private Message(String source, String target, String body, Date timestamp) {
        this.source = source;
        this.target = target;
        this.body = body;
        this.timestamp = timestamp;
    }

    public static class Builder{
        private String source;
        private String target;
        private String body;
        private Date timestamp;

        public Builder setSource(String source) {
            this.source = source;
            return this;
        }

        public Builder setTarget(String target) {
            this.target = target;
            return this;
        }

        public Builder setBody(String body) {
            this.body = body;
            return this;
        }

        public Builder setTimestamp(Date timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Message build() {
            return new Message(source, target, body, timestamp);
        }
    }

}
