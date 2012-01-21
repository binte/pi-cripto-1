package teste;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


public class RW_KeyStore {

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

    public static PrivateKey getPrivateKey(String fileName, String type, String aliasName) throws Exception{

	char[] passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance(type);
	File certificateFile = new File(fileName);

	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Obter a chave privada do KeyPair
        return (PrivateKey) ks.getKey(aliasName, passPhrase);
    }
}
