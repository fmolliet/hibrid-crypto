package io.winty.sec.service.impl;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import io.winty.sec.service.AssymetricService;

public class AssymetricServiceImpl implements AssymetricService {
    
    private Cipher cipher;
    
    private static final String ALGORITM = "RSA/ECB/PKCS1Padding";
    
    private static AssymetricServiceImpl instance;
    
    public static AssymetricService getInstance() throws NoSuchAlgorithmException, NoSuchPaddingException{
        if (instance == null) {
            instance = new AssymetricServiceImpl();
        }
        return instance;
    }
    
    public AssymetricServiceImpl() throws NoSuchAlgorithmException, NoSuchPaddingException{
        cipher = Cipher.getInstance(ALGORITM);
    }
}
