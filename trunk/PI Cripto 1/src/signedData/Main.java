package signedData;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;
import sun.security.x509.CertificateSerialNumber;


public class Main {

    public static void main(String[] args) {

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12",
                cert_alias = "cacert", asym_algorithm, provider = "BC";
        byte[] encrypted, decrypted, digest, attributes;
        Cifra cipher;
        Digest dgst;
        X509Certificate cert;
        Session session;
        MimeMessage msg;
        SMIMESigned signed;
        SMIMEEnveloped enveloped;
        SignerInformationStore signers;
        SignerInformation s;
        CertStore certs;
        Collection c;
        Iterator sig_it, env_it, certIt;
        RecipientInformation ri;
        ByteArrayOutputStream baos;
        ObjectOutputStream oos;


        
        // Se tiver sido passado um parâmetro ao programa
        if( args.length == 1) {

            /**
             * 0 - Path do ficheiro que contém o conteúdo SMIME
             */


            try {
                
                session = Session.getDefaultInstance(System.getProperties());
               
                msg = new MimeMessage(session, new FileInputStream(args[0]));


if(msg.getDataHandler().getContentType().startsWith("multipart/signed")) {

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
                sig_it = c.iterator();

                while(sig_it.hasNext()) {

                    /* Isolar a informação do signatário */
                    s = (SignerInformation) sig_it.next();



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
                        asym_algorithm = SignedHelper.getEncryptionAlgName(s.getEncryptionAlgOID());

                        /* Ler os bytes da assinatura (resumo de mensagem) cifrado */
                        encrypted = s.toASN1Structure().getEncryptedDigest().getOctets();

                        /* Ler os atributos não assinados, sobre os quais foi produzida a assinatura recebida */
                        attributes = s.getEncodedSignedAttributes();


/******************************************************* DEBUG *******************************************************/
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
/******************************************************* DEBUG *******************************************************/
                        

                        /* Criar uma nova instância da classe que vai calcular o resumo da mensagem recebida em claro */
                        dgst = new Digest(signedData.SignedHelper.getDigestAlgName(s.getDigestAlgOID()), provider);

                        /* especificar o algoritmo a ser utilizado na operação de decifragem */
                        cipher = new Cifra(asym_algorithm);

                        // decifrar o resumo de mensagem cifrado através da chave pública lida do certificado do emissor
                        decrypted = cipher.decifrar(encrypted, cert.getPublicKey());


                        /* Calcular o resumo da mensagem (texto limpo) */
                        digest = dgst.computeMessageDigest(attributes);

                        /* Criar um objecto da classe DigestInfo, que irá albergar a informação do digest
                         que vai ser calculado para comparar com o digest lido (após decifragem) da pacote SMIME */
                        PKCS7.DigestInfo digest_info = new PKCS7.DigestInfo(s.getDigestAlgorithmID(), digest);


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
//System.out.println(contentInfo.toString());
}
else if(msg.getDataHandler().getContentType().contains("enveloped-data")) {

enveloped = new SMIMEEnveloped(msg);

//System.out.println("SIM? " + enveloped.getContentInfo().getContentType().equals(ContentInfo.envelopedData));

//System.out.println("enc algorithm " + EnvelopedHelper.getSymmetricCipherName(enveloped.getEncryptionAlgOID()));
//System.out.println("content type " + enveloped.getContentInfo().getContentType());

//System.out.println("EC CT: " + enveloped.getEncryptedContent().getContentType());

//ContentInfo contentInfo = enveloped.getContentInfo();
//System.out.println(contentInfo.getContentType().toString());

//System.out.println("ContentID: " + enveloped.getEncryptedContent().getContentID());


//BASE64DecoderStream b64 = ((BASE64DecoderStream)enveloped.getEncryptedContent().getContent());

//byte[] teste = new byte[b64.available()], teste2;

//b64.read(teste, 0, b64.available());

//System.out.println("LENGTH: " + teste.length);
//System.out.println(new String(teste));

        //enveloped = new SMIMEEnveloped((MimeBodyPart)msg.getContent());
        /*
        MimePart encryptedContent = enveloped.getEncryptedContent();
        BASE64DecoderStream bds = (BASE64DecoderStream) encryptedContent.getContent();

        System.out.println("Filename:"+msg.getFileName());
        System.out.println("EAOID:"+enveloped.getEncryptionAlgOID());
        ContentInfo contentInfo = enveloped.getContentInfo();


        System.out.println("Content info ContentType:"+contentInfo.getContentType());

        System.out.println("EC content type:"+encryptedContent.getContentType());

        byte[] data = new byte[bds.available()];
        bds.read(data, 0, bds.available());*/
        //System.out.println("Data"+Gadgets.asHex(data));

        //leitura da chave privada
PrivateKey pkey = RW_KeyStore.getPrivateKey(ksFile, ks_type, key_alias, Gadgets.getPasswordFromConsole(System.console(), new char[] {'K','e','y','S','t','o','r','e',' ','P','a','s','s','w','o','r','d',':',' '}));


    RecipientInformationStore recipientInfos = enveloped.getRecipientInfos();
            //PKCS7.ContentType contentType = new PKCS7.ContentType(enveloped.getContentInfo().getContentType());
            //ArrayList<PKCS7.EncryptedContentInfo> recipientInfos = new ArrayList<PKCS7.EncryptedContentInfo>();
            //RecipientInformationStore ris  = enveloped.getRecipientInfos();
            //Collection c =  (Collection) ris.getRecipients();

        env_it = recipientInfos.getRecipients().iterator();




/* Content cifrado 
MimePart encryptedContent = enveloped.getEncryptedContent();
InputStream is =encryptedContent.getInputStream();
byte[] aux = new byte[is.available()];
is.read(aux, 0, is.available());

System.out.println("Content");
System.out.println(new String(aux));

System.out.println("!!");
RW_File rw = new RW_File("Signer/signer_key.der");

//Leitura da chave secreta
String algorithm = "AES/CBC/PKCS7Padding";
byte[] bytekey = rw.readByteFile();
SecretKeySpec sps = new SecretKeySpec(bytekey, algorithm);

//Leitura do IV
rw.setFile("Signer/iv.hex");
byte[]iv = rw.readByteFile();
System.out.println(new String(iv));
IvParameterSpec ivs = new IvParameterSpec(iv);


Cifra cifra = new Cifra(algorithm);
decrypted = cifra.decifrar(sps, aux, iv);
System.out.println("Decrypted\n"+new String(decrypted));*/








        while(env_it.hasNext()) {

            ri = (RecipientInformation) env_it.next();

            asym_algorithm = SignedHelper.getEncryptionAlgName(ri.getKeyEncryptionAlgOID());

//System.out.println(ri.getKeyEncryptionAlgParams().length);
//ri.getKeyEncryptionAlgorithmParameters(provider);

            MimeBodyPart res = SMIMEUtil.toMimeBodyPart(ri.getContent(new JceKeyTransEnvelopedRecipient(pkey).setProvider(provider)));

//System.out.println(ri.getRID().getSubjectPublicKeyAlgID());


//teste2 = ri.getContent(new JceKeyTransEnvelopedRecipient(pkey).setProvider(provider));
//System.out.println(teste2.length);
//Cifra cifra = new Cifra(asym_algorithm);
//cifra.decifrar(teste, pkey);
//res = SMIMEUtil.toMimeBodyPart(teste);


//System.out.println("ID: " + res.getContentType());

        if(res.getContentType().equals("text/plain")) {
            
            System.out.println("\n");
            System.out.println("---------------------------------------------------");
            System.out.println("--------------------- Message ---------------------");
            System.out.println("---------------------------------------------------");
            System.out.println(res.getContent());
        }
        else {

//msg = new MimeMessage(session, res.getInputStream());
//System.out.println(msg.getSize());
                
        }
    }

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
