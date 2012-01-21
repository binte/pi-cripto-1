package teste;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.apache.commons.io.IOUtils;

public class MyKeyStoreProvider {

    public static KeyStore getKeystore(char[] password, String path) throws GeneralSecurityException, IOException {

        KeyStore keystore = KeyStore.getInstance("JCEKS");
        InputStream input = new FileInputStream(path);

        try {
            
          keystore.load(input, password);
        }
        catch (IOException e) {
        }
        finally {

          IOUtils.closeQuietly(input);
        }

        return keystore;
    }
}
