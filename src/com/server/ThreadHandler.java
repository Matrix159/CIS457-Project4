package com.server;


import java.io.IOException;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


public class ThreadHandler {
    public ServerSocket serverSocket;
    public boolean running = true;
    public static List<ServerThread> serverThreads = Collections.synchronizedList(new ArrayList<ServerThread>());
    public static List<String> usernames = Collections.synchronizedList(new ArrayList<String>());
    public static GUI gui;
    public Thread thread;
    public ThreadHandler server = this;
    public Crypto crypto = new Crypto();
    public PublicKey pubKey;
    public PrivateKey privKey;
    public ThreadHandler(GUI theGui) {
        try {
            //Generate public and private keys.
            crypto.setPublicKey("RSApub.der");
            crypto.setPrivateKey("RSApriv.der");
            pubKey = crypto.getPublicKey();
            privKey = crypto.getPrivateKey();
            gui = theGui;
            serverSocket = new ServerSocket(44444);
            thread = new Thread(() -> {
                while (running) {
                    try {
                        ServerThread serverThread = new ServerThread(gui, serverSocket.accept(), server, crypto);
                        serverThreads.add(serverThread);
                        serverThread.start();
                    } catch (Exception ex) {
                        Logger.getLogger(ThreadHandler.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
            });
            thread.start();

        } catch (IOException ex) {
            System.out.println("Could not start ServerThread.");
        }
    }

    public static synchronized void removeUser(int i) {
        ThreadHandler.usernames.remove(i);
    }

    public static synchronized void removeThread(ServerThread serverThread) {
        ThreadHandler.serverThreads.remove(serverThread);
    }

}
    
 