package io.winty.sec.service;

import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

public interface KeyManager {
    public SecretKey getSecret();
}
