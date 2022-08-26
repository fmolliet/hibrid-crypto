package io.winty.sec.service;

import javax.crypto.SecretKey;

public interface SymetricService {
    public String encrypt( String data, SecretKey secret ) throws Exception;
}
