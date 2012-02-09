package signedData;

import PKCS7.SignedData;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertStore;
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
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;


public class Main {

    public static void main(String[] args) {

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm, provider = "BC";
        byte[] encrypted, decrypted, digest, attributes;
        Cifra cipher;
        Digest dgst;
        X509Certificate cert;
        Properties props;
        Session session;
        MimeMessage msg;
        SMIMESigned signed;
        SignerInformationStore signers;
        SignerInformation s;
        CertStore certs;
        Collection c;
        Iterator it, certIt;
        ByteArrayOutputStream baos;
        ObjectOutputStream oos;

        
        // Se tiver sido passado um parâmetro ao programa
        if( args.length == 1) {

            /**
             * 0 - Path do ficheiro que contém o conteúdo SMIME
             */


            try {

                props = System.getProperties();
                session = Session.getDefaultInstance(props);

                msg = new MimeMessage(session, new FileInputStream(args[0]));
                signed = new SMIMESigned((MimeMultipart) msg.getContent());

                /* Colocar a informação dos vários signatários (contida no pacote SMIME) numa Collection,
                 de modo a processar a informação de cada um individualmente */
                signers = signed.getSignerInfos();
                c = signers.getSigners();

                /* Ler os certificados do pacote SMIME */
                certs =   (CertStore) signed.getCertificatesAndCRLs("Collection", provider);


//PKCS7.ContentType contentType = new PKCS7.ContentType(signed.getContentInfo().getContentType());
//PKCS7.SignedData signedData = new PKCS7.SignedData(signed.getVersion(), signed.getContent().getContentMD5(), signed.getContentInfo(), signed.getSignerInfos());
//PKCS7.ContentInfo contentInfo = new PKCS7.ContentInfo(contentType, signedData);

//System.out.println(contentInfo.toString());



                /* Iterar os signatários */
                it = c.iterator();

                while(it.hasNext()) {

                    /* Isolar a informação do signatário */
                    s = (SignerInformation) it.next();

                    /* Colocar as cadeias de certificados dos signatários contidos no pacote SMIME numa Collection */
                    Collection certCollection = certs.getCertificates(s.getSID());

                    /* Iterar os certificados da cadeia de certificados que está a ser processada */
                    certIt = certCollection.iterator();
                    cert = (X509Certificate) certIt.next();


                    /* Verificar o certificado do emissor com a CA */
                    if(Certificate_Handler.verifyCertificate(RW_KeyStore.getCertificate(ksFile, ks_type, cert_alias), cert, Security.getProvider(provider))) {

                        /* Ler o identificador do algoritmo utilizado para cifrar o resumo de mensagem */
                        algorithm = Gadgets.getBC_Algorithm(s.getEncryptionAlgOID());

                        /* Ler os bytes da assinatura (resumo de mensagem) cifrado */
                        encrypted = s.toASN1Structure().getEncryptedDigest().getOctets();

                        /* Ler os atributos não assinados, sobre os quais foi produzida a assinatura recebida */
                        attributes = s.getEncodedSignedAttributes();

//Converter isto para um array de bytes e testar a ver se funciona
//signed.getContentInfo().getContent();
                        

//RW_File rw = new RW_File("encrypted");
//rw.writeFile(encrypted);
//
//rw.setFile("encrypted_ssl");
//encrypted2 = rw.readByteFile();

//BASE64Encoder encoder = new BASE64Encoder();
//String encoded = encoder.encode(encrypted);

//BASE64Encoder encoder2 = new BASE64Encoder();
//String encoded2 = encoder2.encode(encrypted2);

//rw.setFile("encoded");
//rw.writeFile(Gadgets.asHex(encrypted));
//
//rw.setFile("encoded2");
//rw.writeFile(Gadgets.asHex(encrypted2));

//System.out.println("Assinatura igual a correcta? " + Arrays.equals(encrypted, encrypted2));


                        /* Criar uma nova instância da classe que vai calcular o resumo da mensagem recebida em claro */
                        dgst = new Digest(Gadgets.getBC_DigestAlgorithm(s.getDigestAlgOID()), provider);

                        /* especificar o algoritmo a ser utilizado na operação de decifragem */
                        cipher = new Cifra(algorithm, provider);

                        // decifrar o resumo de mensagem cifrado através da chave pública lida do certificado do emissor
                        decrypted = cipher.decifrar(encrypted, cert.getPublicKey());

/* Ler os bytes da mensagem (texto limpo) guardada no pacote SMIME para uma OutputStream */
//baos = new ByteArrayOutputStream();
//oos = new ObjectOutputStream(baos);
//oos.writeObject(signed.getContent().getContent());
//oos.close();

                        /* Calcular o resumo da mensagem (texto limpo) */
                        digest = dgst.computeMessageDigest(attributes);

DigestInfo digest_info = new DigestInfo(s.getDigestAlgorithmID(), digest);

Gadgets.printByteArray(digest_info.getEncoded());
Gadgets.printByteArray(decrypted);

//System.out.println("----------------------------------------------------");
//System.out.println(new String(baos.toByteArray()));
//System.out.println("----------------------------------------------------");
//System.out.println((String) signed.getContent().getContent());
//System.out.println("----------------------------------------------------");
//
//baos.close();


if( MessageDigest.isEqual(decrypted, digest_info.getEncoded()) )
    System.out.println("check");
else
    System.out.println("fail");

                        /* Comparar o resumo da mensagem com o resumo de mensagem desencriptado em cima */
//                        if( MessageDigest.isEqual(decrypted, digest) )
//                            System.out.println("check");
//                        else
//                            System.out.println("fail");
                    }
                    else
                        throw new Exception("Invalid Certificate");
                }
            }
            catch (Exception ex) {

                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
            System.err.println("Invalid parameter number: " + args.length);
    }
}
