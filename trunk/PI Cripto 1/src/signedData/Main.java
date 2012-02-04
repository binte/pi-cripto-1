package signedData;

import PKCS7.SignedData;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm, message;
        byte[] encrypted, encrypted2,  decrypted, digest;
        Cifra cipher;
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
             * 1 - Path do ficheiro que contém o conteúdo SMIME
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

PKCS7.ContentType contentType = new PKCS7.ContentType(signed.getContentInfo().getContentType());
PKCS7.SignedData signedData = new PKCS7SignedData(signed.getVersion(), signed.getContent().getContentMD5(), signed.getContentInfo(), signed.getSignerInfos());
PKCS7.ContentInfo contentInfo = new PKCS7.ContentInfo(contentType, signedData);

System.out.println(contentInfo.toString());

                    it = c.iterator();

                    while(it.hasNext()) {

                        /* Isolar a informação do signatário */
                        SignerInformation s = (SignerInformation) it.next();

                        /* Ler o identificador do algoritmo utilizado para encriptar o resumo de mensagem */
                        algorithm = Gadgets.getBC_Algorithm(s.getEncryptionAlgOID());

                        /* Ler os bytes da assinatura (resumo de mensagem) encriptado */
                        encrypted = s.toASN1Structure().getEncryptedDigest().getOctets();

                        /* Guardar a mensagem em claro */
                        message = (String) signed.getContent().getContent();


RW_File rw = new RW_File("encrypted");
rw.writeFile(encrypted);

rw.setFile("encrypted_ssl");
encrypted2 = rw.readByteFile();

System.out.println(Arrays.equals(encrypted, encrypted2));

//Sign sig = new Sign(Gadgets.getBC_DigestAlgorithm(s.getDigestAlgOID()), algorithm);

//System.out.println(sig.verifySign(cert.getPublicKey(), message.getBytes(), encrypted2));

                        /* Criar uma nova instância da classe que vai calcular o resumo da mensagem recebida em claro */
                        dgst = new Digest(Gadgets.getBC_DigestAlgorithm(s.getDigestAlgOID()));

                        /* especificar o algoritmo a ser utilizado na operação de cifragem */
                        cipher = new Cifra(algorithm);

                        // decifrar o resumo de mensagem cifrado através da chave pública lida do certificado do emissor
                        decrypted = cipher.decifrar(encrypted2, cert.getPublicKey());

                        /* Calcular o resumo da mensagem (texto limpo) */
                        digest = dgst.computeMessageDigest(((String)signed.getContent().getContent()).getBytes());


                        /* Comparar o resumo da mensagem com o resumo de mensagem desencriptado em cima */
                        if( MessageDigest.isEqual(decrypted, digest) )
                            System.out.println("check");
                        else
                            System.out.println("fail");
                    }
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
