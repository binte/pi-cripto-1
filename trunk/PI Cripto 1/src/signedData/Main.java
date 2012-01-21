package signedData;

import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main {

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        String ksFile = "Recipient/ks_recipient", ks_type = "JCEKS", key_alias = "recipient_pkcs12", cert_alias = "cacert", algorithm = "RSA";
        byte[] encrypted = null, decrypted, digest;
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




                    SignedData sd = new SignedData( (ASN1Sequence) ((new ASN1InputStream((RW_KeyStore.getCertificate(ksFile, ks_type, key_alias)).getEncoded())).readObject()));
                    ContentInfo ci = sd.getEncapContentInfo();  // retirar a mensagem do pacote

                   // System.out.println(ci.getContent().toString());

                    SignerInfo signerInfo = getSignerInfo(sd);

                    
                    // ler os bytes do ficheiro que contém o resumo de mensagem encriptado
                    // encrypted = (byte[]) proc.getContent();

                    // desencriptar o resumo de mensagem encriptado através da chave privada lida da keystore
                    decrypted = cipher.decifrar(encrypted, RW_KeyStore.export(ksFile, ks_type, key_alias, algorithm));

System.out.println(new String(decrypted));


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

    private static SignerInfo getSignerInfo(SignedData signedData) {

        ASN1Set signerInfos = signedData.getSignerInfos();

        if (signerInfos.size() > 1) {
                System.err.println("WARNING: found " + signerInfos.size() + " signerInfos");
        }

        for (int i = 0; i < signerInfos.size(); i++) {

            SignerInfo info = new SignerInfo((DERSequence)signerInfos.getObjectAt(i));
                return info;
        }

        return null;
    }

    private static ASN1Sequence createCertificate(X509Certificate cert) throws Exception {

        try {
                byte[] certSpec = cert.getEncoded();
                ASN1Sequence certSeq = (ASN1Sequence)(new ASN1InputStream(certSpec)).readObject();
                return certSeq;
        }
        catch (Exception ioe) {
            
                throw new CertificateException("Could not construct certificate byte stream");
        }
    }
}
