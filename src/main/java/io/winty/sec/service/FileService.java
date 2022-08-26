package io.winty.sec.service;

import java.io.IOException;

public interface FileService {
    public byte[] getFileBytes( String keyFilepath )throws IOException ;
}
