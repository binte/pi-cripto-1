package signedData;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;
import sun.security.x509.CertificateSerialNumber;


public class Main {

    public static void main(String[] args) {

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12",
                cert_alias = "cacert", algorithm, provider = "BC";
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
                certs = (CertStore) signed.getCertificatesAndCRLs("Collection", provider);


PKCS7.ContentType contentType = new PKCS7.ContentType(signed.getContentInfo().getContentType());
ArrayList<PKCS7.SignerInfo> signerInfos = new ArrayList<PKCS7.SignerInfo>();

                /* Iterar os signatários */
                it = c.iterator();

                while(it.hasNext()) {

                    /* Isolar a informação do signatário */
                    s = (SignerInformation) it.next();




SignerInformation signerInfoBC = signed.getSignerInfos().get(s.getSID());
PKCS7.IssuerAndSerialNumber isn = new PKCS7.IssuerAndSerialNumber(s.getSID().getIssuer(),
                                                                  new CertificateSerialNumber(s.getSID().getSerialNumber()));
PKCS7.SignerInfo signerInfo = new PKCS7.SignerInfo(signerInfoBC.getVersion(),
                                                   isn,
                                                   signerInfoBC.getDigestAlgorithmID(),
                                                   signerInfoBC.getSignedAttributes().toAttributes(),
                                                   signerInfoBC.toASN1Structure().getDigestEncryptionAlgorithm(),
                                                   signerInfoBC.toASN1Structure().getEncryptedDigest().getOctets(),
                                                   (signerInfoBC.getUnsignedAttributes() == null) ? 
                                                                   null :
                                                                   signerInfoBC.getUnsignedAttributes().toAttributes());

signerInfos.add(signerInfo);


                    /* Colocar as cadeias de certificados dos signatários contidos no pacote SMIME numa Collection */
                    Collection certCollection = certs.getCertificates(s.getSID());

                    /* Iterar os certificados da cadeia de certificados que está a ser processada */
                    certIt = certCollection.iterator();
                    cert = (X509Certificate) certIt.next();


                    /* Verificar o certificado do emissor com a CA */
                    if(Certificate_Handler.verifyCertificate(RW_KeyStore.getCertificate(ksFile, ks_type, cert_alias),
                                                             cert, Security.getProvider(provider))) {

                        /* Ler o identificador do algoritmo utilizado para cifrar o resumo de mensagem */
                        algorithm = SignedHelper.getEncryptionAlgName(s.getEncryptionAlgOID());

                        /* Ler os bytes da assinatura (resumo de mensagem) cifrado */
                        encrypted = s.toASN1Structure().getEncryptedDigest().getOctets();

                        /* Ler os atributos não assinados, sobre os quais foi produzida a assinatura recebida */
                        attributes = s.getEncodedSignedAttributes();
                        

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
                        dgst = new Digest(signedData.SignedHelper.getDigestAlgName(s.getDigestAlgOID()), provider);

                        /* especificar o algoritmo a ser utilizado na operação de decifragem */
                        cipher = new Cifra(algorithm);

                        // decifrar o resumo de mensagem cifrado através da chave pública lida do certificado do emissor
                        decrypted = cipher.decifrar(encrypted, cert.getPublicKey());

/* Ler os bytes da mensagem (texto limpo) guardada no pacote SMIME para uma OutputStream */
//baos = new ByteArrayOutputStream();
//oos = new ObjectOutputStream(baos);
//oos.writeObject(signed.getContent().getContent());
//oos.close();

                        /* Calcular o resumo da mensagem (texto limpo) */
                        digest = dgst.computeMessageDigest(attributes);

                        /* Criar um objecto da classe DigestInfo, que irá albergar a informação do digest
                         que vai ser calculado para comparar com o digest lido (após decifragem) da pacote SMIME */
                        PKCS7.DigestInfo digest_info = new PKCS7.DigestInfo(s.getDigestAlgorithmID(), digest);

//Gadgets.printByteArray(digest_info.getEncoded());
//Gadgets.printByteArray(decrypted);

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
                    }
                    else
                        throw new Exception("Invalid Certificate");
                }

PKCS7.SignedData signedData = new PKCS7.SignedData(signed.getVersion(), signed.getContentInfo(), signerInfos);
PKCS7.ContentInfo contentInfo = new PKCS7.ContentInfo(contentType, signedData);

System.out.println(contentInfo.toString());

            }
            catch (Exception ex) {

                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
            System.err.println("Invalid parameter number: " + args.length);
    }
}
