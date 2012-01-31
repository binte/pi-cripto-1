package signedData;

import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.IOError;
import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;


public class Gadgets {

    public static final String DES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String RC2_CBC = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String IDEA_CBC = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String CAST5_CBC = "1.2.840.113533.7.66.10";
    public static final String AES128_CBC = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String AES192_CBC = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String AES256_CBC = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.getId();
    public static final String CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.getId();
    public static final String CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.getId();
    public static final String SEED_CBC = KISAObjectIdentifiers.id_seedCBC.getId();
    public static final String DES_EDE3_WRAP = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String AES128_WRAP = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String AES256_WRAP = NISTObjectIdentifiers.id_aes256_wrap.getId();
    public static final String CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.getId();
    public static final String CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.getId();
    public static final String CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.getId();
    public static final String SEED_WRAP = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId();
    public static final String ECDH_SHA1KDF = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();

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

    //public static String getBC_Algorithm(String algOID) {


//    }

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
}
