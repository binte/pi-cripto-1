/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package envelopedData;
import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import signedData.Cifra;
import signedData.RW_File;
import signedData.Gadgets;

/**
 *
 * @author joao
 */
public class Main {

    /**
     * arg 1 - path do criptograma
     * arg 2 - path da privateKey do receptor
     * @param args 
     */
    public static void main(String []args) throws IOException, Exception{
        byte[] criptograma,textolimpo;
        RW_File rw;
        Cifra cifra;
        String provider = "BC";
        String algorithm = "RSA";
        PrivateKey prvtkey;
        
        //Leitura do criptograma
        rw= new RW_File(args[0]);
        criptograma = rw.readByteFile();
        
        //Leitura da private Key
        
         prvtkey = Gadgets.readKeyPair(new File(args[1])).getPrivate();
         
         cifra = new Cifra(algorithm,provider);
         textolimpo = cifra.decifrar(criptograma, prvtkey);
        
         System.out.println(new String(textolimpo));
         
        }
}
