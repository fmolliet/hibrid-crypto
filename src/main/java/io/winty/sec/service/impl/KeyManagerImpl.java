package io.winty.sec.service.impl;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.winty.sec.service.KeyManager;

public class KeyManagerImpl implements KeyManager {
    
    private Key key;
    private int operation;
    private SecretKey secret; 
    
    private static final int SIZE = 256;
    private static final String ALGORITM = "RSA";
    
    public KeyManagerImpl(int mode, byte[] keyBytes ) throws InvalidKeySpecException, NoSuchAlgorithmException{
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITM);
        if ( mode == Cipher.ENCRYPT_MODE ){ 
            this.key = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
            this.generateSecretKey();
        } else if ( mode == Cipher.DECRYPT_MODE) {
            this.key =  keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            
        } else {
            throw new SecurityException("Modo de operação inválido, por favor usar ou encrypt ou decrypt");
        }
        this.operation = mode;
    }
    
    public Key getKey(){
        return key;
    }
    
    private void generateSecretKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(SIZE, SecureRandom.getInstanceStrong());
        this.secret = keyGenerator.generateKey();
    }
    
    public SecretKey getSecret() {
        return secret;
    }
    
    public SecretKey setSecret( byte[] encodedKey) {
        this.secret = new SecretKeySpec(encodedKey, "AES" );
        return secret;
    }
    
    public int getOperation() {
        return operation;
    }

}
