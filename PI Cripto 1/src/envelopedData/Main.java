/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package envelopedData;
import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import signedData.Cifra;
import signedData.RW_File;
import signedData.Gadgets;
import signedData.RW_KeyStore;

/**
 *
 * @author joao
 */
public class Main {

    /**
     * arg 1 - path do chave secreta encriptada
     * arg 2 - path da privateKey do receptor
     * arg 3 - path do iv
     * arg 4 - path do salt
     * arg 5 - path do criptograma
     * @param args 
     */
    public static void main(String []args) throws IOException, Exception{
        
        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS",
                key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm, provider = "BC";
        char[] passphrase = {'1','2','3','4','5','6'};
        byte[] criptograma,textolimpo,iv,salt,keydata;
        RW_File rw;
        Cifra cifra;
        algorithm = "AES/CBC";
        
        PrivateKey prvtkey;
        File file;
        
        //Leitura do array da secretKey
        rw= new RW_File(args[0]);
        keydata = rw.readByteFile();
        SecretKeySpec sks = new SecretKeySpec (keydata,algorithm);
        
        
        //leitura do iv
        rw.setFile(args[2]);
        iv = rw.readByteFile();
        
        //leitura do salt
        
        rw.setFile(args[3]);
        salt = rw.readByteFile();
        
        //Leitura do criptograma
        
        rw.setFile(args[4]);
        criptograma = rw.readByteFile();
        
        //Leitura da private Key
        cifra  = new Cifra(algorithm,provider);
        textolimpo = cifra.decifrar(keydata, sks);
        System.out.println(new String(textolimpo));
        }
}
