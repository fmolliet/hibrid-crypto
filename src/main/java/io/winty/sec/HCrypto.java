package io.winty.sec;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.winty.sec.service.AssymetricService;
import io.winty.sec.service.FileService;
import io.winty.sec.service.KeyManager;
import io.winty.sec.service.SymetricService;
import io.winty.sec.service.impl.AssymetricServiceImpl;
import io.winty.sec.service.impl.FileServiceImpl;
import io.winty.sec.service.impl.KeyManagerImpl;
import io.winty.sec.service.impl.SymetricServiceImpl;

public class HCrypto {

    private FileService fileService = new FileServiceImpl();
    private KeyManager keyManager; 
    private AssymetricService assymetricService; 
    private SymetricService symetricService; 
    
    private static final int KEY_LEN_INFO = 4;

    public HCrypto( int mode, String keyFilepath ) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException  {
        byte[] keyBytes = fileService.getFileBytes(keyFilepath);
        this.loadServices(mode, keyBytes);
    }
    
    public HCrypto( int mode, Key key  ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException  {
        this.loadServices(mode, key.getEncoded());
    }
    
    private void loadServices(int mode, byte[]  keyBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        symetricService = SymetricServiceImpl.getInstance();
        assymetricService = new AssymetricServiceImpl();
        keyManager = new KeyManagerImpl(mode, keyBytes);
    }
    
    private byte[] encryptData(String data) throws Exception {
        return this.symetricService.encrypt(data, this.keyManager.getSecret());
    }
    
    private byte[] encryptKey( ) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        byte[] key = keyManager.getSecret().getEncoded();
        return this.assymetricService.encrypt(key, this.keyManager.getKey());
    }
    
    public String encrypt(String data) throws Exception {
        
        // Encrypt Data
        byte[] encryptedData = this.encryptData(data);
        
        // EncryptKey
        byte[] encryptedKey = encryptKey();
        byte[] keySize = ByteBuffer.allocate(KEY_LEN_INFO).putInt(encryptedKey.length).array();
        
        return Base64.getEncoder().encodeToString(
            buildPayload(keySize, encryptedKey,encryptedData)
        );
    }
    
    public String decrypt(String data) throws Exception{
        // Decode
        byte[] cryptogram = Base64.getDecoder().decode(data);
        
        // Extract payload
        byte[] encryptedKey = extractKeyPayload(cryptogram);
        byte[] encryptedData =extractDataPayload(cryptogram, encryptedKey);
       
        // DecryptKey
        byte[] decryptedKey = this.assymetricService.decrypt(encryptedKey, this.keyManager.getKey());
        this.keyManager.setSecret(decryptedKey);
        
        // Decrypt Data
        return this.symetricService.decrypt(encryptedData, keyManager.getSecret());
    }
    
    private byte[] buildPayload(byte [] keySize, byte[] encryptedKey, byte[] encryptedData ){
         // build cryptogram
         byte[] cryptogram = new byte[keySize.length+ encryptedKey.length + encryptedData.length];
        
         // Concat bytes
         System.arraycopy(keySize, 0, cryptogram, 0, keySize.length);
         System.arraycopy(encryptedKey, 0, cryptogram, keySize.length, encryptedKey.length);
         System.arraycopy(encryptedData, 0, cryptogram, encryptedKey.length + keySize.length, encryptedData.length);
         
         return cryptogram;
    }
    
    private byte[] extractKeyPayload( byte[] cryptogram){
        byte[] keySize = new byte[KEY_LEN_INFO];
        // Extract key and cipherData
        System.arraycopy(cryptogram, 0, keySize, 0, KEY_LEN_INFO);
 
        return new byte[new BigInteger(keySize).intValue()];
    }
    
    private byte[] extractDataPayload( byte[] cryptogram, byte[] encryptedKey){
        byte[] encryptedData = new byte[cryptogram.length-encryptedKey.length-KEY_LEN_INFO];
         
        System.arraycopy(cryptogram, KEY_LEN_INFO, encryptedKey, 0, encryptedKey.length);
        System.arraycopy(cryptogram, encryptedKey.length+KEY_LEN_INFO, encryptedData, 0, encryptedData.length);
 
        return encryptedData;
        
    }

}
