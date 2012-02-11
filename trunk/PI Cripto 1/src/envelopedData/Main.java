/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package envelopedData;
import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import signedAndEnvelopedData.Cifra;
import signedAndEnvelopedData.RW_File;
import signedAndEnvelopedData.Gadgets;
//import signedAndEnvelopedData.RW_KeyStore;

/**
 *
 * @author joao
 */
public class Main {

    /**
     * arg 0 - path do chave secreta encriptada
     * arg 1 - path da privateKey do receptor
     * arg 2 - path do iv
     * arg 3 - path do criptograma
     * @param args 
     */
    public static void main(String []args) throws IOException, Exception{
        String sym_algorithm = "AES/CBC/PKCS7Padding", asym_algorithm = "RSA", provider = "BC",
                digest_algorithm = "SHA-256";
        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS",
                key_alias = "recipient_pkcs12", cert_alias = "cacert";
        char[] passphrase = {'1','2','3','4','5','6'};
        byte[] encrypted,decrypted,iv,salt,keydata,aux;
        RW_File rw;
        Cifra cipher;
        SecretKeySpec skey;
        
        //Leitura do array da secretKey
        rw= new RW_File(args[0]);
        encrypted = rw.readByteFile();
        
        //Decifragem do array de bytes secretkey
        cipher = new Cifra(asym_algorithm,provider);
        cipher.setFile(args[1]);
        aux = cipher.decifrar(encrypted);
                
        //decrypted = new byte[32];
        decrypted = Arrays.copyOfRange(aux, aux.length-32, aux.length);
        
        //Obter finalmente a secretkey, depois de mudado para algoritmo simétrico
        cipher.setAlgorithm(sym_algorithm);
        String s = new String(decrypted);
        skey = cipher.build_key(Gadgets.hexStringToByteArray(s));
        
        //leitura do iv
        rw.setFile(args[2]);
        iv = rw.readByteFile();
        
        
        //leitura do criptograma
        rw.setFile(args[4]);
        encrypted = rw.readByteFile();
        
        //Decifrar o criptograma
        
        decrypted = cipher.decifrar(skey, encrypted, Gadgets.hexStringToByteArray(new String(iv)));
        
        System.out.println(new String(decrypted));
        
        
        
        }
}
