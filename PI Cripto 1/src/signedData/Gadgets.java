package signedData;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOError;
import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;


public class Gadgets {

    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();



    public static final String pkcs_1 = "1.2.840.113549.1.1";
    public static final String pkcs_7 = "1.2.840.113549.1.7";

    private static final String CERTIFICATE_MANAGEMENT_CONTENT = "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only";
    private static final String DETACHED_SIGNATURE_TYPE = "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
    private static final String ENCAPSULATED_SIGNED_CONTENT_TYPE = "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data";

    public static final String data = pkcs_7 + ".1";
    public static final String signedData = pkcs_7 + ".2";
    public static final String envelopedData = pkcs_7 + ".3";
    public static final String signedAndEnvelopedData = pkcs_7 + ".4";
    public static final String digestedData = pkcs_7 + ".5";
    public static final String encryptedData = pkcs_7 + ".6";



    
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
    public static String asHex(byte[] buf) {

        int i;
        char[] chars = new char[2 * buf.length];
        
        for (i=0 ; i < buf.length ; i++) {
            
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        
        return new String(chars);
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

    public static String getContentType(String contentTypeOID) {

        String contentType;

        if(contentTypeOID.equals(data))
            contentType = "data";
        else if(contentTypeOID.equals(signedData))
            contentType = "signedData";
        else if(contentTypeOID.equals(envelopedData))
            contentType = "envelopedData";
        else if(contentTypeOID.equals(signedAndEnvelopedData))
            contentType = "signedAndEnveloped";
        else if(contentTypeOID.equals(digestedData))
            contentType = "digestedData";
        else if(contentTypeOID.equals(encryptedData))
            contentType = "encryptedData";
        else
            contentType = "unknown";

        return contentType;
    }

    public static String concatDigestWithEncryptionAlgorithm(String dgst_algorithm, String algorithm){

        StringBuilder sb = new StringBuilder();

        sb.append(dgst_algorithm + "With" + algorithm);

        return sb.toString();
    }

    /***
     * Codificar em bytes um dado Object
     *
     * @param Object
     *
     * @return byte[] com a sequência de bytes relativa ao objecto
     */
    public static byte[] getEncoded(Object obj) throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
        aOut.writeObject(obj);

        return bOut.toByteArray();
    }
}
