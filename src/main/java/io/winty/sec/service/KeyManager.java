package io.winty.sec.service;

import java.security.Key;

import javax.crypto.SecretKey;

public interface KeyManager {
    public SecretKey getSecret();
    public SecretKey setSecret( byte[] encodedKey);
    public Key getKey();
}
