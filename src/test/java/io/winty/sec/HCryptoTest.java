package io.winty.sec;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
/**
 * Unit test for simple App.
 */
public class HCryptoTest 
{
    
    HCrypto encryptInstance;
    HCrypto decryptInstance;
    
    /**
     * Realiza a insatancia dos modos de decrypt e encrypt
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws NoSuchProviderException
     */
    @BeforeEach
    public void init() throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        encryptInstance = new HCrypto(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        decryptInstance = new HCrypto(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    }
    
    /**
     * Dado que a classe HCrypto é instanciada como modo de encrypt
     * Quando é recebido um valor para realizar encrypt
     * Então a instancia realizará o encrypt dos valores.
     * @throws Exception
     */
    @Test
    public void testEncryptData() throws Exception
    {
        this.init();
        assertEquals(false, encryptInstance.encrypt("test").isEmpty());
    }
    
    /**
     * Dado que é recebido um dado encryptado
     * Quando classe HCrypto é instanciada no modo decrypt
     * Então a instancia realizará o decrypt dos valores]
     * E deverá retornar o valor de cryptado
     * @throws Exception
     */
    @Test
    public void testDecryptData() throws Exception
    {
        this.init();
        String plaintext = "test";
        String encryptedData = encryptInstance.encrypt(plaintext);
        assertEquals(plaintext, decryptInstance.decrypt(encryptedData) );
    }
}
