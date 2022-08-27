package io.winty.sec.service;

import javax.crypto.SecretKey;

public interface SymetricService {
    public byte[] encrypt( String data, SecretKey secret ) throws Exception;
    public String decrypt( byte[] data, SecretKey secret ) throws Exception;
}
