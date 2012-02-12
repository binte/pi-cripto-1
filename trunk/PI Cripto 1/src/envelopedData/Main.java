/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package envelopedData;

//import PKCS7.EncryptedContentInfo;
import PKCS7.EncryptedContentInfo;
import com.sun.mail.util.BASE64DecoderStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.cms.KEKRecipientInformation;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;
import smimeReader.Cifra;
import smimeReader.RW_File;
import signedAndEnvelopedData.Gadgets;
import smimeReader.EnvelopedHelper;
import smimeReader.SignedHelper;
import sun.security.x509.CertificateSerialNumber;

//import signedAndEnvelopedData.RW_KeyStore;

/**
 *
 * @author joao
 */
public class Main {

    /**
     * arg 0 - path do chave secreta encriptada
     * arg 1 - path da privateKey do receptor
     * arg 2 - path do iv
     * arg 3 - path da MimeMessage
     * @param args 
     */
    public static void main(String []args) throws IOException, Exception{
        String sym_algorithm = "AES/CBC/PKCS7Padding", asym_algorithm, provider = "BC",
                digest_algorithm = "SHA-256";
        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS",
                key_alias = "recipient_pkcs12", cert_alias = "cacert";
        char[] passphrase = {'1','2','3','4','5','6'};
        byte[] encrypted,decrypted,iv,salt,keydata,aux;
        RW_File rw ;
        Cifra cipher;
        SecretKeySpec skey;
        String algorithm;
        
        //Variáveis SMIME
        Session session;
        MimeMessage msg;
        SMIMEEnveloped enveloped;
        EncryptedContentInfo eci;
        RecipientInformation ri;
        MimePart mp;
        
        if(args.length == 3){
        
        //Inicializar a sessão    
        session = Session.getDefaultInstance(System.getProperties());
        
        //Criação da MIMEMessage
        
        msg = new MimeMessage(session,new FileInputStream(args[0]));
        rw = new RW_File(args[0]);
        byte[]file = rw.readByteFile();
        //ASN1Sequence asn1seq = ASN1Sequence.getInstance(file);
        
        rw.setFile(args[2]);
        byte[] bytekey = rw.readByteFile();
        System.out.println(new String(Gadgets.asHex(bytekey)));
        
        enveloped = new SMIMEEnveloped(msg);

//System.out.println("SIM? " + enveloped.getContentInfo().getContentType().equals(ContentInfo.envelopedData));

System.out.println("enc algorithm " + EnvelopedHelper.getSymmetricCipherName(enveloped.getEncryptionAlgOID()));
System.out.println("content type " + enveloped.getContentInfo().getContentType());

System.out.println("EC CT: " + enveloped.getEncryptedContent().getContentType());

ContentInfo contentInfo = enveloped.getContentInfo();
System.out.println(contentInfo.getContentType().toString());

System.out.println("ContentID: " + enveloped.getEncryptedContent().getContentID());
        

BASE64DecoderStream b64 = ((BASE64DecoderStream)enveloped.getEncryptedContent().getContent());

byte[] teste = new byte[b64.available()], teste2;

b64.read(teste, 0, b64.available());

System.out.println("LENGTH: " + teste.length);
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
        
        PrivateKey pkey = Gadgets.readKeyPair(new File(args[1])).getPrivate();
        
        
        RecipientInformationStore recipientInfos = enveloped.getRecipientInfos();
            //PKCS7.ContentType contentType = new PKCS7.ContentType(enveloped.getContentInfo().getContentType());
            //ArrayList<PKCS7.EncryptedContentInfo> recipientInfos = new ArrayList<PKCS7.EncryptedContentInfo>();
            //RecipientInformationStore ris  = enveloped.getRecipientInfos();
            //Collection c =  (Collection) ris.getRecipients();
        
        Iterator it = recipientInfos.getRecipients().iterator();
                
        
        
        while(it.hasNext()){
            
            ri = (RecipientInformation) it.next();

            asym_algorithm = SignedHelper.getEncryptionAlgName(ri.getKeyEncryptionAlgOID());
System.out.println(ri.getKeyEncryptionAlgParams().length);
ri.getKeyEncryptionAlgorithmParameters(provider);

            MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(ri.getContent(new JceKeyTransEnvelopedRecipient(pkey).setProvider(provider)));

System.out.println(ri.getRID().getSubjectPublicKeyAlgID());


teste2 = ri.getContent(new JceKeyTransEnvelopedRecipient(pkey).setProvider(provider));
System.out.println(teste2.length);
//Cifra cifra = new Cifra(asym_algorithm);
//cifra.decifrar(teste, pkey);
//res = SMIMEUtil.toMimeBodyPart(teste);


            System.out.println("\n\n\nMessage:");
            System.out.println(res.getContent());
            /*       
            byte[] keyEncryptionAlgParams = nri.getKeyEncryptionAlgParams();
            if(keyEncryptionAlgParams.length==0) System.out.println("lixo");
            else System.out.println("length:"+keyEncryptionAlgParams.length);
            System.out.println("keyEncryptionAlgParams:"+new String(keyEncryptionAlgParams));
            
            //Ler o algoritmo utilizado para cifrar a mensagem depois de obtio o seu OID
            String keyEncryptionAlgOID = nri.getKeyEncryptionAlgOID();
            algorithm = signedData.SignedHelper.getEncryptionAlgName(keyEncryptionAlgOID);
            System.out.println("algorithm:"+algorithm);
            
            
            System.out.println("Content Digest:"+nri.getContentDigest());*/
            //System.out.println(""+nri.toA);
            
            
            //Leitura do array de bytes correspondente à chave secreta cifrada com a chave pública do receptor
            //System.out.println(new String(ri.getKeyEncryptionAlgorithmParameters(Security.getProvider(provider)).getAlgorithm()));
            
        }
        
        
        
            /*
            rw= new RW_File(args[0]);
            encrypted = rw.readByteFile();
            //Decifragem do array de bytes secretkey
            cipher = new Cifra(asym_algorithm);
            cipher.setFile(args[1]);
            decrypted = cipher.decifrar(encrypted);
            System.out.println(new String(decrypted));
            //decrypted = new byte[32];
            //decrypted = Arrays.copyOfRange(aux, aux.length-32, aux.length);
            //Obter finalmente a secretkey, depois de mudado para algoritmo simétrico
            cipher.setAlgorithm(sym_algorithm);
            String s = new String(decrypted);
            skey = cipher.build_key(Gadgets.hexStringToByteArray(s));
            //leitura do iv
            rw.setFile(args[2]);
            iv = rw.readByteFile();
            //leitura do criptograma
            rw.setFile(args[3]);
            encrypted = rw.readByteFile();
            //Decifrar o criptograma
            decrypted = cipher.decifrar(skey, encrypted, Gadgets.hexStringToByteArray(new String(iv)));
            System.out.println(new String(decrypted));*/
        }
        
        }
}
