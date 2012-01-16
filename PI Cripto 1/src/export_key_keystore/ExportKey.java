
// http://javaalmanac.com/egs/java.security/GetKeyFromKs.html


package export_key_keystore;

import java.security.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import signedData.Gadgets;
import signedData.RW_File;

public class ExportKey {

    /**
     * Imprimir a chave privada no formato PEM
     *
     * @param int com a flag que indica se é suposto exportar a chave pública a privada
     * @param String contendo o nome do ficheiro da keystore
     * @param String contendo o alias do Certificado no qual está contida a chave privada
     */
    public static void export(int flag, String fileName, String aliasName) throws Exception{

	char[] b64, passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance("JKS");
	File certificateFile = new File(fileName);
        StringBuilder sb = new StringBuilder();
        KeyPair kp;


	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Ler o keyPair da KeyStore
	kp = getKeyPair(ks, aliasName, passPhrase);


        if(flag == 1) {

            PublicKey pubKey = kp.getPublic();

            b64 = Base64Coder.encode(pubKey.getEncoded());

            sb.append("-----BEGIN PUBLIC KEY-----");
            sb.append(base64simple2base64PEM(b64));
            sb.append("\n-----END PUBLIC KEY-----\n");
        }

        if(flag == 2) {

            PrivateKey privKey = kp.getPrivate();

            b64 = Base64Coder.encode(privKey.getEncoded());

            sb.append("-----BEGIN PRIVATE KEY-----");
            sb.append(base64simple2base64PEM(b64));
            sb.append("\n-----END PRIVATE KEY-----\n");
        }

        System.out.print(sb.toString());
    }

    /**
     * Imprimir a chave privada no formato PEM para um dado ficheiro
     *
     * @param int com a flag que indica se é suposto exportar a chave pública a privada
     * @param String contendo o nome do ficheiro da keystore
     * @param String contendo o alias do Certificado no qual está contida a chave privada
     * @param String com o nome do ficheiro de output
     */
    public static void export(int flag, String fileName, String aliasName, String outFile) throws Exception{
        
	char[] b64, passPhrase = Gadgets.getPasswordFromConsole(System.console(), new char[] {'P','a','s','s','w','o','r','d',':',' '});
	KeyStore ks = KeyStore.getInstance("JKS");
	File certificateFile = new File(fileName);
        RW_File rw = new RW_File(outFile);
        StringBuilder sb = new StringBuilder();
        KeyPair kp;


	ks.load(new FileInputStream(certificateFile), passPhrase);

        // Ler o keyPair da KeyStore
	kp = getKeyPair(ks, aliasName, passPhrase);

        
        if(flag == 1) {

            PublicKey pubKey = kp.getPublic();

            b64 = Base64Coder.encode(pubKey.getEncoded());

            sb.append("-----BEGIN PUBLIC KEY-----");
            sb.append(base64simple2base64PEM(b64));
            sb.append("\n-----END PUBLIC KEY-----\n");
        }

        if(flag == 2) {

            PrivateKey privKey = kp.getPrivate();

            b64 = Base64Coder.encode(privKey.getEncoded());

            sb.append("-----BEGIN PRIVATE KEY-----");
            sb.append(base64simple2base64PEM(b64));
            sb.append("\n-----END PRIVATE KEY-----\n");
        }

        rw.writeFile(sb.toString());
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
    private static KeyPair getKeyPair(KeyStore keystore, String alias, char[] password) {
       
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

    private static String base64simple2base64PEM(char[] b64) {

        int i, j;
        StringBuilder sb = new StringBuilder();

        for(i=0, j=0 ; i<b64.length ; j++) {

            if(j%65 != 0)
                sb.append(b64[i++]);
            else
                sb.append('\n');
        }

        return sb.toString();
    }
}
