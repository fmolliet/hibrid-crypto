package io.winty.sec;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class HCrypto {
    
    private Key key;
    private int operation;

    public HCrypto( int mode, String keyFilepath ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        File keyFile = new File(keyFilepath);
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        
        if ( mode == Cipher.ENCRYPT_MODE ){
            this.key = keyFactory.generatePublic(keySpec);
        } else if ( mode == Cipher.DECRYPT_MODE) {
            this.key = keyFactory.generatePrivate(keySpec);
        } else {
            throw new RuntimeException("Modo de operação inválido, por favor usar ou encrypt ou decrypt");
        }
        this.operation = mode;
    }
    
    //TODO: implementar
    public String encrypt( String data){
        return null;
    }
    
    //TODO: implementar
    public String decrypt(String data){
        return null;
    }
}
