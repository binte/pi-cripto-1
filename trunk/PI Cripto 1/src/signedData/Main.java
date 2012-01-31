package signedData;

import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;


public class Main {

    public static void main(String[] args) {

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm = "RSA";
        byte[] encrypted, decrypted, digest;
        Cifra cipher = new Cifra(algorithm);
        Digest dgst;
        X509Certificate cert;
        Properties props;
        Session session;
        MimeMessage msg;
        SMIMESigned signed;
        SignerInformationStore signer;
        Collection c;
        Iterator it;

        // Se tiverem sido passados três parâmetros ao programa
        if( args.length == 2) {

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


                    props = System.getProperties();
                    session = Session.getDefaultInstance(props);

                    msg = new MimeMessage(session, new FileInputStream(args[1]));
                    signed = new SMIMESigned((MimeMultipart) msg.getContent());

                    signer = signed.getSignerInfos();

                    c = signer.getSigners();

                    
                    it = c.iterator();

                    while(it.hasNext()) {

                        SignerInformation s = (SignerInformation) it.next();

                        algorithm = s.getEncryptionAlgOID();

                        encrypted = s.getEncodedSignedAttributes();

                        dgst = new Digest(Gadgets.getBC_DigestAlgorithm(s.getDigestAlgOID()));


                    // ler os bytes do ficheiro que contém o resumo de mensagem encriptado
                    //encrypted = rw.readByteFile();

                    // desencriptar o resumo de mensagem encriptado através da chave privada lida da keystore
                    decrypted = cipher.decifrar(encrypted, RW_KeyStore.export(ksFile, ks_type, key_alias, algorithm));

                    

                    /* Definir o ficheiro da mensagem, de forma a recebê-la independentemente */
                    //rw.setFile(args[2]);

                    /* Calcular o resumo da mensagem */
                    digest = dgst.computeMessageDigest(((String)signed.getContent().getContent()).getBytes());


                    /* Comparar o resumo da mensagem com o resumo de mensagem desencriptado em cima */
                    if( MessageDigest.isEqual(decrypted, digest) )
                        System.out.println("check");
                    else
                        System.out.println("fail");}
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
