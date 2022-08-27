package io.winty.sec.service.impl;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import io.winty.sec.service.SymetricService;

public class SymetricServiceImpl implements SymetricService {
    
    private static SymetricServiceImpl instance;
    
    private Cipher cipher;
    
    private static final int IV_SIZE = 16;
    
    private static final String ALGORITM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
    public static SymetricService getInstance() throws NoSuchAlgorithmException, NoSuchPaddingException{
        if (instance == null) {
            instance = new SymetricServiceImpl();
        }
        return instance;
    }
    
    public SymetricServiceImpl() throws NoSuchAlgorithmException, NoSuchPaddingException {
        cipher = Cipher.getInstance(ALGORITM);
    }
    
    private byte[] encrypt(byte[] text, SecretKey secret, byte[] iv) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        return cipher.doFinal(text);
    }
    
    private String decrypt(byte[] text, SecretKey secret, byte[]  iv) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(text);
        return new String(plainText, UTF_8);
    }
    
    public String decrypt(byte[] data, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(data);
        
        byte[] iv = new byte[IV_SIZE];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        return decrypt(cipherText, secret, iv);
    }
    
    public byte[] encrypt( String data, SecretKey secret ) throws Exception{
        
        byte[] iv = this.getRandomNonce(IV_SIZE);
        byte[] cipherText = encrypt(data.getBytes(), secret, iv);
        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;
    }
    
    private byte[] getRandomNonce(int size) {
        byte[] nonce = new byte[size];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

}
