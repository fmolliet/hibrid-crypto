package io.winty.sec.service.impl;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import io.winty.sec.service.FileService;

public class FileServiceImpl implements FileService {

    public byte[] getFileBytes(String keyFilepath) throws IOException {
        File keyFile = new File(keyFilepath);
        String key = new String(Files.readAllBytes(keyFile.toPath()), StandardCharsets.UTF_8);

        String keyPEM = key
            .replaceAll("(-----(BEGIN|END) ?(\\w*\\s)\\w* KEY-----)", "")
            .replaceAll(System.lineSeparator(), "");
            
        return Base64.getDecoder().decode(keyPEM);
    }
    
}
