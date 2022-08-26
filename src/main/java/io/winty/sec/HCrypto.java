package io.winty.sec;

import java.io.IOException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

    public HCrypto( int mode, String keyFilepath ) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
        byte[] keyBytes = fileService.getFileBytes(keyFilepath);
        this.addProviders();
        this.setOperationMode(mode, keyBytes);
        this.loadServices();
    }
    
    private void addProviders(){
        java.security.Security.addProvider(
         new BouncyCastleProvider());
    }

    private void loadServices() throws NoSuchAlgorithmException, NoSuchPaddingException{
        symetricService = SymetricServiceImpl.getInstance();
        assymetricService = AssymetricServiceImpl.getInstance();
    }
    
    
    private void setOperationMode(int mode, byte[]  keyBytes ) throws NoSuchAlgorithmException, InvalidKeySpecException{
        keyManager = KeyManagerImpl.getInstance( mode,  keyBytes );
    }
    
    
    public String encrypt(String data) throws Exception {
        return this.symetricService.encrypt(data, this.keyManager.getSecret());
    }
    

    //TODO: implementar
    public String decrypt(String data){
        return null;
    }

}
