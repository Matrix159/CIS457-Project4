package com.client;

import com.shared.Message;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Client {
    public volatile ObjectOutputStream out;
    public ObjectInputStream in;
    private static Thread readThread;
    private static Thread outputThread;
    public GUI gui;
    public String ip;
    public int position;
    public boolean connected = false;
    public InetSocketAddress socketAddress;
    public boolean downloading = false;
    public File fileToSaveTo;
    public ArrayList<byte[]> byteList = new ArrayList<byte[]>();
    public long byteCounter = 0;
    public long byteLength = 0;
    public Socket clientSocket;
    SecretKey sKey;
    PublicKey pubKey;
    IvParameterSpec iv;
    public Client(GUI gui, String ip) {
        this.gui = gui;
        this.ip = ip;
        sKey = generateAESKey();
        System.out.printf("Client Key: %s%n",DatatypeConverter.printHexBinary(sKey.getEncoded()));
    }

    public void startClient() {


        try {
            clientSocket = new Socket();
            socketAddress = new InetSocketAddress(ip, 44444);
            if (socketAddress.isUnresolved()) {
                throw new IllegalArgumentException();
            }
            clientSocket.connect(socketAddress, 2500);
            gui.messageTextArea.append("Connected to server." + "\n");
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());

            // Encryption setup
            waitForPubKey(in);
            byte[] encryptedSecretKey = RSAEncrypt(sKey.getEncoded());
            int size = encryptedSecretKey.length;
            out.writeInt(size);
            out.flush();
            out.write(encryptedSecretKey);
            out.flush();

            connected = true;
            out.writeObject(new Message(Message.LOGON, gui.usernameField.getText()));
            gui.username = gui.usernameField.getText();
            gui.usernameField.setEditable(false);
            readThread = new Thread(new Runnable() {
                String text;

                public void run() {
                    try {
                        while (connected) {
                            Message message = (Message) in.readObject();
                            if(message.content != null) {
                                System.out.printf("CipherText: %s%n", DatatypeConverter.printHexBinary(message.content));
                                message.content = decrypt(message.content, sKey, new IvParameterSpec(message.secureRandom));
                            }
                            System.out.println("Received message.");
                            switch (message.type) {
                                case Message.MESSAGE_ALL:
                                    gui.messageTextArea.append(message.toString() + "\n");
                                    break;
                                case Message.MESSAGE:
                                    gui.messageTextArea.append(message.toString() + "\n");
                                    break;
                                case Message.LOGON:
                                    //System.out.println(message.usernames.size());
                                    //gui.listModel.addElement(message.username);
                                    gui.listModel.clear();
                                    gui.listModel.ensureCapacity(message.usernames.size() + 1);

                                    for (int i = 0; i < message.usernames.size(); i++) {
                                        if (i == 0)
                                            gui.listModel.add(i, "All");
                                        gui.listModel.add(i + 1, message.usernames.get(i));
                                        System.out.println(message.usernames.get(i));
                                    }
                                    gui.userList.setSelectedIndex(0);

                                    break;
                                case Message.LOGOUT:
                                    /*for(int i = 0; i < message.usernames.size(); i++)
                                    {
                                        gui.listModel.set(i + 1, message.usernames.get(i));
                                    }*/

                                    gui.listModel.removeElement(message.username);
                                    break;
                                case Message.KICK:
                                    if(message.username.equalsIgnoreCase(gui.username)) {
                                        if (connected) {
                                            try {
                                                out.writeObject(new Message(Message.LOGOUT, gui.username));
                                                closeClient();
                                                gui.usernameField.setEditable(true);
                                            } catch (IOException ex) {
                                                System.out.println("Issue closing client socket.");
                                            }
                                        }
                                    }
                                    break;
                                case Message.SERVER_SHUTDOWN:
                                    closeClient();
                                    break;
                                /*case Message.UPLOAD_REQ:
                                    System.out.println("Received upload request");
                                    if (downloading) {
                                        out.writeObject(new Message(Message.UPLOAD_DENY, message.username, new byte[0], gui.username));
                                        break;
                                    }
                                    int x = JOptionPane.showConfirmDialog(gui, message.username + " would like to send you " + message.content + " (" + (message.getFileLength() / 1024 / 1024) + "MB)", "Download Request", JOptionPane.YES_NO_OPTION);
                                    if (x == JOptionPane.YES_OPTION) {
                                        JFileChooser fileChooser = new JFileChooser();
                                        fileChooser.setSelectedFile(new File(new String(message.getContent())));
                                        int i = fileChooser.showSaveDialog(gui);
                                        if (i == JFileChooser.APPROVE_OPTION) {
                                            fileToSaveTo = fileChooser.getSelectedFile();
                                            System.out.println(fileToSaveTo.toString());
                                            System.out.println(message.dataLength);
                                            byteLength = message.getFileLength();
                                            gui.progressBar.setMaximum((int) byteLength);
                                            System.out.println("Attempting to send out upload accept");
                                            Download download = new Download(fileToSaveTo, byteLength, gui, gui.client);
                                            Thread downloadThread = new Thread(download, "Download Thread");
                                            downloadThread.start();
                                            out.reset();
                                            out.writeObject(new Message(Message.UPLOAD_ACCEPT, message.username, "", gui.username));

                                            System.out.println("Sent out upload accept");
                                        } else if (i == JFileChooser.CANCEL_OPTION) {
                                            out.reset();
                                            out.writeObject(new Message(Message.UPLOAD_DENY, message.username, "", gui.username));
                                            System.out.println("No sent to user.");
                                        }
                                        break;
                                    } else if (x == JOptionPane.NO_OPTION) {
                                        out.reset();
                                        out.writeObject(new Message(Message.UPLOAD_DENY, message.username, "", gui.username));
                                        System.out.println("No sent to user.");
                                    }
                                    break;*/
                                case Message.UPLOAD_ACCEPT:
                                    System.out.println("Received upload accept");
                                    gui.fileTextField.setEditable(false);
                                    gui.chooseDownFileButton.setEnabled(false);
                                    gui.sendFileButton.setEnabled(false);
                                    File file = new File(gui.fileTextField.getText());
                                    Upload upload = new Upload(gui.username, message.username, file, gui);
                                    Thread thread = new Thread(upload, "Upload Thread");
                                    thread.start();
                                    System.out.println("Upload thread started.");
                                    break;
                                case Message.UPLOAD_DENY:
                                    System.out.println("Received upload deny.");
                                    gui.messageTextArea.append(message.username + " denied file transfer.\n");
                                    break;


                            }
                        }
                    } catch (IOException ex) {
                        System.out.println("Could not read message.");
                    } catch (ClassNotFoundException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        try {
                            out.flush();
                            clientSocket.close();
                        } catch (IOException ex) {
                            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }, "Client Read Thread");
            readThread.start();
        } catch (SocketTimeoutException ex) {
            ex.printStackTrace();
            gui.messageTextArea.append("Connection timed out." + "\n");
        } catch (IllegalArgumentException ex) {
            ex.printStackTrace();
            gui.messageTextArea.append("Given address is not reachable." + "\n");
        } catch (IOException ex) {
            ex.printStackTrace();
            gui.messageTextArea.append("Could not connect to server." + "\n");
        }

    }

    public SecretKey generateAESKey(){
        try{
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secKey = keyGen.generateKey();
            return secKey;
        }catch(Exception e){
            System.out.println("Key Generation Exception");
            return null;
        }
    }

    public byte[] RSAEncrypt(byte[] plaintext) throws IOException {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] ciphertext = c.doFinal(plaintext);
            return ciphertext;
        } catch (Exception e) {
            System.out.println("RSA Encrypt Exception");
            return null;
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

    private void waitForPubKey(ObjectInputStream in){
        try{
            byte[] info = new byte[294];
            in.read(info);
            X509EncodedKeySpec keyspec = new X509EncodedKeySpec(info);
            KeyFactory rsafactory = KeyFactory.getInstance("RSA");
            pubKey = rsafactory.generatePublic(keyspec);
            byte[] secureBytes = new byte[16];
            in.read(secureBytes);
            iv = new IvParameterSpec(secureBytes);
        } catch(Exception e){
            System.out.println("Public Key Exception");
        }
    }

    public void closeClient() throws IOException {
        clientSocket.close();
        connected = false;
        gui.listModel.clear();
    }
}
        
                    
                    