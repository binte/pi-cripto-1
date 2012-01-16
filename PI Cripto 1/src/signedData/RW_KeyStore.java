package signedData;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;


public class RW_KeyStore {

    /**
     * Writes a keystore to a filesystem
     */
    public static void writeKeyStoreToFile(KeyStore keyStore, File file, char[] masterPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        FileOutputStream out = new FileOutputStream(file);

        try {

            //Gravar a keystore no ficheiro
            keyStore.store(out, masterPassword );
        }
        finally {
            
            out.close();
        }
    }

    /**
     * Reads key from keystore on a filesystem
     *
     * @param String com o tipo de keystore (JCEKS, JKS, PKCS12, etc)
     */
    public static PrivateKey ReadKeyFromStore(File file, String type, String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

        PrivateKey keyFromStore = null;
        KeyStore keyStore = KeyStore.getInstance(type);
        char[] masterPassword = Gadgets.getPasswordFromConsole(System.console(), new char[] {'P','a','s','s','w','o','r','d',':',' '});
        
        if ( file.exists() ) {

            FileInputStream input = new FileInputStream(file);
            keyStore.load(input, masterPassword);
            input.close();
        }

        // Ler a SecretKey da KeyStore gravada em ficheiro
        keyFromStore = (PrivateKey) keyStore.getKey(alias, masterPassword);

        return keyFromStore;
    }

    /**
     * Ler e retornar a chave privada contida na keystore
     *
     * @param String contendo o nome do ficheiro da keystore
     * @param String com o tipo de keystore (JCEKS, JKS, PKCS12, etc)
     * @param String contendo o alias do Certificado no qual está contida a chave privada
     * @param String com o algoritmo de chave pública utilizado
     *
     * @return PrivateKey com a chave privada contida na keystore
     */
    public static PrivateKey export(String fileName, String type, String aliasName, String algorithm) throws Exception{

	char[] passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'K','e','y','S','t','o','r','e',' ','P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance(type);
	File certificateFile = new File(fileName);

	ks.load(new FileInputStream(certificateFile), passPhrase);

        PrivateKey privKey = getPrivateKey(fileName, type, aliasName, passPhrase);

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        KeySpec kspec = new PKCS8EncodedKeySpec(privKey.getEncoded());
        RSAPrivateKey RSAprivKey = (RSAPrivateKey) keyFactory.generatePrivate(kspec);

        return RSAprivKey;
    }

    /**
     * Ler uma KeyPair duma KeyStore
     *
     * @param KeyStore contendo o certificado
     * @param alias do certificado
     * @param password
     *
     * @return KeyPair com o par de chaves contido no certificado
     */
    public static KeyPair getKeyPair(KeyStore keystore, String alias, char[] password) {

        try
        {
            // Get private key
            Key key = keystore.getKey(alias, password);

            if (key instanceof PrivateKey) {

                // Get certificate of public key
                X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                // Return a key pair
                return new KeyPair(publicKey, (PrivateKey)key);
            }
        }
        catch (Exception e) {

        }

        return null;
    }

    /**
     * Ler o Certificado da CA no formato PEM, guardado numa KeyStore
     *
     * @param String contendo o nome do ficheiro da keystore
     * @param String com o tipo de keystore (JCEKS, JKS, PKCS12, etc)
     * @param String contendo o alias do Certificado da CA
     *
     * @return X509Certificate
     */
    public static X509Certificate getCertificate(String fileName, String type, String aliasName) throws Exception{

	char[] passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'K','e','y','S','t','o','r','e',' ','P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance(type);
	File certificateFile = new File(fileName);

	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Obter o certificado da CA do KeyPair
        return (X509Certificate) ks.getCertificate(aliasName);
    }

    /**
     * Ler uma chave privada no formato PEM, guardada num certificado (utilizado no standard PKCS12)
     *
     * @param String contendo o nome do ficheiro da keystore
     * @param String com o tipo de keystore (JCEKS, JKS, PKCS12, etc)
     * @param String contendo o alias do Certificado no qual está contida a chave privada
     *
     * @return PrivateKey
     */
    public static PrivateKey getPrivateKey(String fileName, String type, String aliasName) throws Exception{

	char[] passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance(type);
	File certificateFile = new File(fileName);

	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Obter a chave privada do KeyPair
        return (PrivateKey) ks.getKey(aliasName, passPhrase);
    }

    /**
     * Ler uma chave privada no formato PEM, guardada num certificado (utilizado no standard PKCS12). Para tal será
     * necessário especificar a password da chave privada
     *
     * @param String contendo o nome do ficheiro da keystore
     * @param String com o tipo de keystore (JCEKS, JKS, PKCS12, etc)
     * @param String contendo o alias do Certificado no qual está contida a chave privada
     * @param char[] com a palavra chave da keystore
     *
     * @return PrivateKey
     */
    public static PrivateKey getPrivateKey(String fileName, String type, String aliasName, char[] passPhrase) throws Exception{

	KeyStore ks = KeyStore.getInstance(type);
	File certificateFile = new File(fileName);

	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Obter a chave privada da KeyStore
        return (PrivateKey) ks.getKey(aliasName, Gadgets.getPasswordFromConsole(System.console(), new char[] {'K','e','y',' ','P','a','s','s','w','o','r','d',':',' '}));
    }
}
