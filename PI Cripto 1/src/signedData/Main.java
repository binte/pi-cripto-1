package signedData;

import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;


public class Main {

    public static void main(String[] args) {

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm = "RSA";
        byte[] encrypted, decrypted, digest;
        Cifra cipher = new Cifra(algorithm);
        Digest dgst = new Digest("SHA-256", 32);
        RW_File rw;
        X509Certificate cert;
        

        // Se tiverem sido passados três parâmetros ao programa
        if( args.length == 3) {

            /**
             * 0 - Path do ficheiro que contém o certificado do emissor (formato DER)
             * 1 - Path do ficheiro que contém o resumo de mensagem encriptado
             * 2 - Path do ficheiro que contém a mensagem
             */


            try {
                

                /************************************/
                /* Receber o Certificado do Emissor */
                /************************************/
                

                /* Criar um objecto com o Certificado do Emissor */
                cert = Certificate_Handler.getCertFromFile(args[0]);
                
                /* Verificar o certificado do emissor com a CA */
                if(Certificate_Handler.verifyCertificate(RW_KeyStore.getCertificate(ksFile, ks_type, cert_alias), cert)) {



                    /***********************************/
                    /* Enviar o Certificado ao Emissor */
                    /***********************************/
                    


                    rw = new RW_File(args[1]);

                    // ler os bytes do ficheiro que contém o resumo de mensagem encriptado
                    encrypted = rw.readByteFile();



                    
                    CMSSignedData sd = Gadgets.getSignedData(new FileInputStream(args[1]));
                    CMSProcessable proc = sd.getSignedContent();
                    ContentInfo ci = sd.getContentInfo();
                    System.out.println(new String(ci.getEncoded()));



                    // desencriptar o resumo de mensagem encriptado através da chave privada lida da keystore
                    decrypted = cipher.decifrar(encrypted, RW_KeyStore.export(ksFile, ks_type, key_alias, algorithm));

                    


                    /* Definir o ficheiro da mensagem, de forma a recebê-la independentemente */
                    rw.setFile(args[2]);

                    /* Calcular o resumo da mensagem */
                    digest = dgst.computeMessageDigest(rw.readByteFile());


                    /* Comparar o resumo da mensagem com o resumo de mensagem desencriptado em cima */
                    if( MessageDigest.isEqual(decrypted, digest) )
                        System.out.println("check");
                    else
                        System.out.println("fail");
                }
                else
                    throw new Exception("Invalid Certificate");
            }
            catch (Exception ex) {

                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
            System.err.println("Invalid parameter number: " + args.length);
    }
}
