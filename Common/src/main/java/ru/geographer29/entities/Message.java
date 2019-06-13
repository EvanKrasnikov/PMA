package ru.geographer29.entities;

import java.util.Date;

public class Message {

    private String source;
    private String target;
    private String body;
    private Date timestamp;

    public String getSource() {
        return source;
    }

    public Message setSource(String source) {
        this.source = source;
        return this;
    }

    public String getTarget() {
        return target;
    }

    public Message setTarget(String target) {
        this.target = target;
        return this;
    }

    public String getBody() {
        return body;
    }

    public Message setBody(String body) {
        this.body = body;
        return this;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public Message setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
        return this;
    }
}
