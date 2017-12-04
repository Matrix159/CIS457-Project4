package com.server;

import com.shared.Message;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @author joseldridge15
 */
public class ServerThread extends Thread {
    public ThreadHandler server;
    public Thread serverThread;
    public Socket clientSocket;
    public volatile ObjectOutputStream out;
    public ObjectInputStream in;
    public GUI gui;
    public boolean connected;
    public int position;
    public String username;
    public Crypto crypto;
    SecretKey clientSecretKey;

    public ServerThread(GUI gui, Socket clientSocket, ThreadHandler server, Crypto crypto) {
        this.gui = gui;
        this.clientSocket = clientSocket;
        this.server = server;
        this.crypto = crypto;
    }

    public synchronized void sendMessage(Message message) throws IOException {
        out.writeObject(message);
    }

    public synchronized void sendEncryptedMessage(int type, Message message) throws IOException {
        SecureRandom r = new SecureRandom();
        byte[] secureRandomBytes = new byte[16];
        r.nextBytes(secureRandomBytes);

        if(type == Message.MESSAGE_ALL) {
            Message copy = new Message(Message.MESSAGE_ALL, message.username, message.content.clone(), secureRandomBytes);
            if(copy.content != null) {
                byte ciphertext[] = encrypt(copy.content, clientSecretKey, new IvParameterSpec(secureRandomBytes));
                copy.content = ciphertext;
                System.out.println("Sent message: " + new String(copy.content, "UTF-8"));
            }
            out.writeObject(copy);
        } else {
            Message copy = new Message(Message.MESSAGE, message.recipient, message.content.clone(), message.username, secureRandomBytes);
            if(copy.content != null) {
                byte ciphertext[] = encrypt(copy.content, clientSecretKey, new IvParameterSpec(secureRandomBytes));
                copy.content = ciphertext;
                System.out.println("Sent message: " + new String(copy.content, "UTF-8"));
            }
            out.writeObject(copy);
        }
    }

    public void run() {

        try {
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());
            connected = true;
            byte[] keyBytes = crypto.getPublicKey().getEncoded();
            System.out.println(keyBytes.length);
            out.write(keyBytes);
            out.flush();
            int size = in.readInt();
            byte[] encryptedSecret = new byte[size];
            in.read(encryptedSecret, 0, size);

            // Get the clients symmetric key
            byte decryptedSecret[] = crypto.RSADecrypt(encryptedSecret);
            clientSecretKey = new SecretKeySpec(decryptedSecret,"AES");
            System.out.printf("Client Key: %s%n",DatatypeConverter.printHexBinary(clientSecretKey.getEncoded()));

            while (connected) {
                try {
                    Message message = (Message) in.readObject();
                    if(message.content != null && message.content.length > 0) {
                        System.out.printf("CipherText: %s%n",DatatypeConverter.printHexBinary(message.content));
                        message.content = decrypt(message.content, clientSecretKey, new IvParameterSpec(message.secureRandom));
                        System.out.println("Received Message: " + new String(message.content, "UTF-8"));
                    }

                    switch (message.type) {
                        case Message.MESSAGE:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.get(i).username.equals(message.recipient)) {
                                    ThreadHandler.serverThreads.get(i).sendEncryptedMessage(Message.MESSAGE, message);
                                }
                            }

                            break;
                        case Message.MESSAGE_ALL:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.get(i) != null && ThreadHandler.serverThreads.get(i) != this) {
                                    ThreadHandler.serverThreads.get(i).sendEncryptedMessage(Message.MESSAGE_ALL, message);
                                }
                            }
                            System.out.println("Sent message to users.");
                            break;
                        case Message.LOGON:
                            username = message.username;
                            ThreadHandler.usernames.add(username);
                            gui.serverUserList.addElement(username);
                            for (int x = 0; x < ThreadHandler.usernames.size(); x++)
                                System.out.println(ThreadHandler.usernames.get(x));
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                ThreadHandler.serverThreads.get(i).out.reset();
                                //ThreadHandler.serverThreads.get(i).out.flush();
                                ThreadHandler.serverThreads.get(i).sendMessage(new Message(Message.LOGON, ThreadHandler.usernames));


                            }

                            break;
                        case Message.LOGOUT:
                            for (int i = 0; i < ThreadHandler.usernames.size(); i++) {
                                if (ThreadHandler.usernames.get(i).equals(message.username))
                                    ThreadHandler.removeUser(i);
                            }
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.indexOf(this) != i) {
                                    ThreadHandler.serverThreads.get(i).out.reset();
                                    ThreadHandler.serverThreads.get(i).out.flush();
                                    ThreadHandler.serverThreads.get(i).sendMessage(new Message(Message.LOGOUT, message.username));

                                }
                            }
                            connected = false;
                            ThreadHandler.removeThread(this);
                            gui.serverUserList.removeElement(message.username);
                            break;
                        case Message.KICK:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.indexOf(this) != i) {
                                    ThreadHandler.serverThreads.get(i).out.reset();
                                    ThreadHandler.serverThreads.get(i).out.flush();
                                    ThreadHandler.serverThreads.get(i).sendMessage(new Message(Message.KICK, message.username));
                                }
                            }
                            break;
                        case Message.UPLOAD_REQ:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.get(i).username.equals(message.recipient)) {
                                    ThreadHandler.serverThreads.get(i).sendMessage(message);
                                }
                            }
                            break;
                        case Message.UPLOAD_ACCEPT:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.get(i).username.equals(message.recipient)) {
                                    ThreadHandler.serverThreads.get(i).sendMessage(message);
                                }
                            }
                            break;
                        case Message.UPLOAD_DENY:
                            for (int i = 0; i < ThreadHandler.serverThreads.size(); i++) {
                                if (ThreadHandler.serverThreads.get(i).username.equals(message.recipient)) {
                                    ThreadHandler.serverThreads.get(i).sendMessage(message);
                                }
                            }
                            break;

                    }
                }//End of try inside While Loop
                catch (ClassNotFoundException ex) {
                    ex.printStackTrace();
                }

            }//End of While Loop
        }//End of run try block 
        catch (IOException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch(Exception ex) {
            ex.printStackTrace();
        } finally {
            close();
        }

    }
    public byte[] encrypt(byte[] plaintext, SecretKey secKey, IvParameterSpec iv){
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE,secKey,iv);
            byte[] ciphertext = c.doFinal(plaintext);
            return ciphertext;
        }catch(Exception e){
            System.out.println("AES Encrypt Exception");
            return null;
        }
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey secKey, IvParameterSpec iv){
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE,secKey,iv);
            byte[] plaintext = c.doFinal(ciphertext);
            return plaintext;
        }catch(Exception e){
            System.out.println("AES Decrypt Exception");
            return null;
        }
    }
    public void close() {
        try {

            if (clientSocket != null) {
                out.flush();
                clientSocket.close();
                clientSocket = null;
            }
        } catch (IOException ex) {
            System.out.println(ex);
        }

    }
}