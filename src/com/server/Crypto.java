package com.server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class Crypto {
    private PrivateKey privKey;
    private PublicKey pubKey;
    
    public Crypto(){
	    privKey=null;
	    pubKey=null;
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
    public byte[] RSADecrypt(byte[] ciphertext){
	    try{
	        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
	        c.init(Cipher.DECRYPT_MODE,privKey);
	        byte[] plaintext = c.doFinal(ciphertext);
	        return plaintext;
	    }catch(Exception e){
	        System.out.println("RSA Decrypt Exception");
	        return null;
	    }
    }
    public byte[] RSAEncrypt(byte[] plaintext){
	    try{
	        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
	        c.init(Cipher.ENCRYPT_MODE,pubKey);
	        byte[] ciphertext = c.doFinal(plaintext);
	        return ciphertext;
	    }catch(Exception e){
	        System.out.println("RSA Encrypt Exception");
	        return null;
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
    public void setPrivateKey(String filename){
	    try{
	        File f = new File(filename);
	        FileInputStream fs = new FileInputStream(f);
	        byte[] keybytes = new byte[(int)f.length()];
	        fs.read(keybytes);
	        fs.close();
	        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(keybytes);
	        KeyFactory rsafactory = KeyFactory.getInstance("RSA");
	        privKey = rsafactory.generatePrivate(keyspec);
	    }catch(Exception e){
	        System.out.println("Private Key Exception");
	        e.printStackTrace(System.out);
	    }
    }
    public void setPublicKey(String filename){
	    try{
	        File f = new File(filename);
	        FileInputStream fs = new FileInputStream(f);
	        byte[] keybytes = new byte[(int)f.length()];
	        fs.read(keybytes);
	        fs.close();
	        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keybytes);
	        KeyFactory rsafactory = KeyFactory.getInstance("RSA");
	        pubKey = rsafactory.generatePublic(keyspec);
	    }catch(Exception e){
	        System.out.println("Public Key Exception");
	    }
    }

    public PublicKey getPublicKey(){
        return pubKey;
    }
    public PrivateKey getPrivateKey(){
        return privKey;
    }
}

