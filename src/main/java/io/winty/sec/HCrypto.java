package io.winty.sec;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.acl.NotOwnerException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.winty.sec.service.FileService;
import io.winty.sec.service.impl.FileServiceImpl;

public class HCrypto {
    
    private Key key;
    private SecretKey secret; 
    private int operation;
    
    private Cipher aesCipher;
    private Cipher rsaCipher;
    
    
    private static final int IV_SIZE = 16;
    private static final int AES_SIZE = 256;
    private static final String RSA_ALGORITM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
    private FileService fileService = new FileServiceImpl();

    public HCrypto( int mode, String keyFilepath ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
        byte[] keyBytes = fileService.getFileBytes(keyFilepath);
        this.addProviders();
        this.setOperationMode(mode, keyBytes);
        this.initCiphers();
    }
    
    private void addProviders(){
        java.security.Security.addProvider(
         new BouncyCastleProvider());
    }
    
    private void initCiphers() throws NoSuchAlgorithmException, NoSuchPaddingException{
        rsaCipher = Cipher.getInstance(RSA_ALGORITM);
        aesCipher = Cipher.getInstance(AES_ALGORITM);
    }
    
    
    
    private void setOperationMode(int mode, byte[]  keyBytes ) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        if ( mode == Cipher.ENCRYPT_MODE ){
            this.key = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
            this.generateSecretKey();
        } else if ( mode == Cipher.DECRYPT_MODE) {
            this.key = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } else {
            throw new RuntimeException("Modo de operação inválido, por favor usar ou encrypt ou decrypt");
        }
        this.operation = mode;
    }
    
    private void generateSecretKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_SIZE, SecureRandom.getInstanceStrong());
        this.secret = keyGenerator.generateKey();
    }
    
    private byte[] getRandomNonce(int size) {
        byte[] nonce = new byte[size];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private byte[] aesEncrypt(byte[] text, SecretKey secret, byte[] iv) throws Exception {
        aesCipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        return aesCipher.doFinal(text);
    }
    
    public String encrypt( String data ) throws Exception{
        
        byte[] iv = this.getRandomNonce(IV_SIZE);
        byte[] cipherText = aesEncrypt(data.getBytes(), secret, iv);
        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return new String(cipherTextWithIv);
    }
    
    //TODO: implementar
    public String decrypt(String data){
        return null;
    }

}
