package signedData;

import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;


public class Gadgets {

    /**
     * Imprimir um array de bytes, byte a byte
     *
     * @param byte[]
     */
    public static void printByteArray(byte[] array){

        System.out.println("--------");

        for (byte b : array)
          System.out.println(Integer.toHexString(b));

        System.out.println("--------");
    }

    /**
     * Converter um array de bytes numa String em formato hexadecimal
     *
     * @param array de bytes que se pretende converter
     *
     * @return String no formato hexadecimal
     */
    public static String asHex(byte buf[]) {

        int i;
        StringBuffer strbuf = new StringBuffer(buf.length * 2);

        for (i = 0; i < buf.length; i++) {

            if(((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
    }

    /**
     * Substituir todos os bytes dum array de bytes pelo byte 0x00, por forma a prevenir rastreios de memória
     *
     * @param array de bytes que se pretende "apagar"
     */
    public static void erase(byte[] bs) {

        for(byte b: bs)
            b = 0x00;
    }

    /**
     * Substituir todos os caracteres dum array de caracteres pelo caracter 'c',
     * de modo a prevenir rastreios de memória
     *
     * @param array de caracteres que se pretende "apagar"
     */
    public static void erase(char[] cs) {

        for(char c: cs)
            c = '\0';
    }
    /**
     * Concatena as chaves públicas do cliente e do servidor por esta ordem
     * 
     * @param serverkey
     * @param clientkey
     * 
     * @return
     */
    public static byte[] concatKeys(String serverkey, String clientkey) throws IOException{
        
        RW_File rw = new RW_File(clientkey);
        byte[] client = rw.readByteFile();
        rw.setFile(serverkey);
        byte[] server = rw.readByteFile();
        int clength = client.length;
        int length = clength + server.length;
        byte[] aux = new byte[length];
        System.arraycopy(client, 0, aux, 0, clength);
        System.arraycopy(server, 0, aux, clength, length - clength);
        
        return aux;
    }

    /**
     * Ler uma KeyPair do ficheiro recebido por parâmetro.
     *
     * @param Ficheiro contendo um par de chaves no formato PEM
     *
     * @return KeyPair lida do ficheiro
     */
    public static KeyPair readPrivateKey(File privateKey) throws Exception {

        FileReader fileReader = new FileReader(privateKey);
        PEMReader r = new PEMReader(fileReader);  // Classe implementada pela biblioteca BouncyCastle

        try {

            return (KeyPair) r.readObject();
        }
        catch (Exception ex) {

            throw new Exception("The private key could not be decrypted", ex);
        }
        finally {

            r.close();
            fileReader.close();
        }
    }
        
    public static KeyPair readKeyPair(File privateKey) throws Exception {

        FileReader fileReader = new FileReader(privateKey);
        Password pass = new Password("1234");
        PEMReader r = new PEMReader(fileReader,pass);  // Classe implementada pela biblioteca BouncyCastle
        
        try {

            return (KeyPair) r.readObject();
        }
        catch (Exception ex) {
            
            throw new Exception("The private key could not be decrypted", ex);
        } 
        finally {
            
            r.close();
            fileReader.close();
        }
    }

    /**
     * Ler uma KeyPair do ficheiro recebido por parâmetro.
     *
     * @param Ficheiro contendo um par de chaves no formato PEM
     *
     * @return KeyPair lida do ficheiro
     */
    public static JCERSAPrivateCrtKey readKeyPair2(File privateKey) throws Exception {

        FileReader fileReader = new FileReader(privateKey);
        Password pass = new Password("1234");
        PEMReader r = new PEMReader(fileReader,pass);  // Classe implementada pela biblioteca BouncyCastle

        try {

            return (JCERSAPrivateCrtKey) r.readObject();
        }
        catch (Exception ex) {

            throw new Exception("The private key could not be decrypted", ex);
        }
        finally {

            r.close();
            fileReader.close();
        }
    }

    /**
     *
     * @param Console através da qual será lida uma password
     * @param char[] contendo os caracteres que serão apresentados ao utilizador, indicando o pedido da password
     * 
     * @return char[] com a password lida
     */
    public static char[] getPasswordFromConsole(Console con, char[] instructions) throws IOError {

        char[] ret = null;

        do {

            for(char c: instructions)
                con.printf("%c", c);

            // Garantir que mesmo a expressão 'Password: ' é apagada
            erase(instructions);

            ret = con.readPassword();

            if(ret == null || ret.length == 0)
                con.printf("Invalid! Please retype.\n");
        }
        while(ret == null || ret.length == 0);

        return ret;
    }

    public static CMSSignedData getSignedData(byte[] signedData) throws Exception {

        return new CMSSignedData(signedData);
    }

    public static CMSSignedData getSignedData(InputStream is) throws Exception {

        return new CMSSignedData(is);
    }
}
