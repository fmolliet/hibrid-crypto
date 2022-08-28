package io.winty.sec.service.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import io.winty.sec.service.AssymetricService;

public class AssymetricServiceImpl implements AssymetricService {
    
    private static final String ALGORITM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    
    @Override
    public byte[] encrypt( byte[] data , Key publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(ALGORITM);
        cipher.init(Cipher.PUBLIC_KEY, publicKey );
        cipher.update(data);
        return cipher.doFinal();
    }

    @Override
    public byte[] decrypt(byte[] data , Key privateKey ) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(ALGORITM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
}
