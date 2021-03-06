package com.shared;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Message implements Serializable {
    public int position;
    public int type;
    public String recipient;
    public byte[] content;
    public String username;
    public List<String> usernames;
    public byte[] fileData;
    public byte[] secureRandom;
    public long dataLength;
    public int bytesSent;
    public final static int MESSAGE = 0, MESSAGE_ALL = 1, LOGON = 2, LOGOUT = 3
            , SERVER_SHUTDOWN = 4, UPLOAD_REQ = 5, UPLOAD_DENY = 6
            , UPLOAD_ACCEPT = 7, FILE = 8, KICK = 9;

    /**
     * Creates a Message object to be sent over the stream.
     * It can contain a user message or file data.
     *
     * @param type      The type of message.
     * @param recipient Who the message is going to in the server.
     * @param content   String content of message.
     * @param username  The username of the sender.
     */
    //Message.MESSAGE
    public Message(int type, String recipient, byte[] content, String username, byte[] secureRandom) {
        this.type = type;
        this.recipient = recipient;
        this.content = content;
        this.username = username;
        this.secureRandom = secureRandom;
    }

    //Message.LOGON to client
    public Message(int type, List<String> usernames) {
        this.type = type;
        this.usernames = usernames;
    }
    //Message.LOGON from client

    public Message(int type, String username) {
        this.type = type;
        this.username = username;
    }

    //Message.ALL
    public Message(int type, String username, byte[] content, byte[] secureRandom) {
        this.type = type;
        this.username = username;
        this.content = content;
        this.secureRandom = secureRandom;
    }

    //Message.SERVER_SHUTDOWN
    public Message(int type) {
        this.type = type;
    }

    //Message.FILE
    public Message(int type, String username, String recipient, byte[] fileData, int bytesSent) {
        this.type = type;
        this.username = username;
        this.recipient = recipient;
        this.fileData = fileData;
        this.bytesSent = bytesSent;

    }

    //Message.UPLOAD_REQ
    public Message(int type, String recipient, byte[] content, long dataLength, String username) {
        this.type = type;
        this.recipient = recipient;
        this.content = content;
        this.dataLength = dataLength;
        this.username = username;
    }

    public long getFileLength() {
        return dataLength;
    }

    public int getPosition() {
        return position;
    }

    public int getType() {
        return type;
    }

    public String getRecipient() {
        return recipient;
    }

    public byte[] getContent() {
        return content;
    }

    public byte[] getByteData() {
        return fileData;
    }

    @Override
    public String toString() {
        return "[" + username + "] " + new String(content);
    }
}
