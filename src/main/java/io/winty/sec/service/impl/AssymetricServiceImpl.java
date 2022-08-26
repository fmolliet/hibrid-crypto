package io.winty.sec.service.impl;

import javax.crypto.Cipher;

import io.winty.sec.service.AssymetricService;

public class AssymetricServiceImpl implements AssymetricService {
    
    private Cipher cipher;
    
    private static final String ALGORITM = "RSA/ECB/PKCS1Padding";
    
    private static AssymetricServiceImpl instance;
    
    public static AssymetricService getInstance(){
        if (instance == null) {
            instance = new AssymetricServiceImpl();
        }
        return instance;
    }
}
