package signedData;

import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOError;
import java.io.IOException;
import java.security.KeyPair;

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

    public static final String pkcs_1 = "1.2.840.113549.1.1";

    public static final DERObjectIdentifier rsaEncryption = new DERObjectIdentifier(pkcs_1 + ".1");
    public static final DERObjectIdentifier md2WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".2");
    public static final DERObjectIdentifier md4WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".3");
    public static final DERObjectIdentifier md5WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".4");
    public static final DERObjectIdentifier sha1WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".5");
    public static final DERObjectIdentifier srsaOAEPEncryptionSET = new DERObjectIdentifier(pkcs_1 + ".6");
    public static final DERObjectIdentifier id_RSAES_OAEP = new DERObjectIdentifier(pkcs_1 + ".7");
    public static final DERObjectIdentifier id_mgf1 = new DERObjectIdentifier(pkcs_1 + ".8");
    public static final DERObjectIdentifier id_pSpecified = new DERObjectIdentifier(pkcs_1 + ".9");
    public static final DERObjectIdentifier id_RSASSA_PSS = new DERObjectIdentifier(pkcs_1 + ".10");
    public static final DERObjectIdentifier sha256WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".11");
    public static final DERObjectIdentifier sha384WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".12");
    public static final DERObjectIdentifier sha512WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".13");
    public static final DERObjectIdentifier sha224WithRSAEncryption = new DERObjectIdentifier(pkcs_1 + ".14");

    public static final String DIGEST_SHA1 = OIWObjectIdentifiers.idSHA1.getId();
    public static final String DIGEST_MD5 = PKCSObjectIdentifiers.md5.getId();
    public static final String DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();
    public static final String DIGEST_GOST3411 = CryptoProObjectIdentifiers.gostR3411.getId();
    public static final String DIGEST_RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128.getId();
    public static final String DIGEST_RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160.getId();
    public static final String DIGEST_RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256.getId();
    public static final String ENCRYPTION_RSA = PKCSObjectIdentifiers.rsaEncryption.getId();
    public static final String ENCRYPTION_DSA = X9ObjectIdentifiers.id_dsa_with_sha1.getId();
    public static final String ENCRYPTION_ECDSA = X9ObjectIdentifiers.ecdsa_with_SHA1.getId();
    public static final String ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers.id_RSASSA_PSS.getId();
    public static final String ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94.getId();
    public static final String ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001.getId();

    private static final String CERTIFICATE_MANAGEMENT_CONTENT = "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only";
    private static final String DETACHED_SIGNATURE_TYPE = "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
    private static final String ENCAPSULATED_SIGNED_CONTENT_TYPE = "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data";

    
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

    public static String getBC_Algorithm(String algOID) {

        String algorithm = new String();
        
        if (algOID.equals(rsaEncryption.toString()))
            algorithm = "rsa";
        else if (algOID.equals(md2WithRSAEncryption.toString()))
            algorithm = "MD2WithRSAEncryption";
        else if (algOID.equals(md4WithRSAEncryption.toString()))
            algorithm = "MD4WithRSAEncryption";
        else if (algOID.equals(md5WithRSAEncryption.toString()))
            algorithm = "MD5WithRSAEncryption";
        else if (algOID.equals(sha1WithRSAEncryption.toString()))
            algorithm = "SHA1WithRSAEncryption";
        else if (algOID.equals(sha256WithRSAEncryption.toString()))
            algorithm = "SHA256WithRSAEncryption";
        else if (algOID.equals(sha384WithRSAEncryption.toString()))
            algorithm = "SHA384WithRSAEncryption";
        else
            algorithm = "unknown";

        return algorithm;
    }

    public static String getBC_DigestAlgorithm(String algOID) {

        String digestAlgorithm;

        if (algOID.equals(DIGEST_SHA1))
            digestAlgorithm = "sha1";
        else if (algOID.equals(DIGEST_MD5))
            digestAlgorithm = "md5";
        else if (algOID.equals(DIGEST_SHA224))
            digestAlgorithm = "sha224";
        else if (algOID.equals(DIGEST_SHA256))
            digestAlgorithm = "sha256";
        else if (algOID.equals(DIGEST_SHA384))
            digestAlgorithm = "sha384";
        else if (algOID.equals(DIGEST_SHA512))
            digestAlgorithm = "sha512";
        else if (algOID.equals(DIGEST_GOST3411))
            digestAlgorithm = "gostr3411-94";
        else
            digestAlgorithm = "unknown";

        return digestAlgorithm;
    }

    public static String concatDigestWithEncryptionAlgorithm(String dgst_algorithm, String algorithm){

        StringBuilder sb = new StringBuilder();

        sb.append(dgst_algorithm + "With" + algorithm);

        return sb.toString();
    }
}
