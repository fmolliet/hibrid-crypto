package io.winty.sec;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
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
    
    @BeforeEach
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException{
        encryptInstance = new HCrypto(Cipher.ENCRYPT_MODE, "src/test/resource/key-pub.pem");
        decryptInstance = new HCrypto(Cipher.DECRYPT_MODE, "src/test/resource/key.pem");
    }
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue()
    {
        
        assertTrue( true );
    }
}
