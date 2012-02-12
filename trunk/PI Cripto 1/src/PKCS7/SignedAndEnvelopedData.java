/*
 *                  SignedAndEnvelopedData ::= SEQUENCE { version Version,
                                                          recipientInfos RecipientInfos,
                                                          digestAlgorithms DigestAlgorithmIdentifiers,
                                                          encryptedContentInfo EncryptedContentInfo,
                                                          certificates ExtendedCertificatesAndCertificates,
                                                          crls CertificateRevocationLists,
                                                          signerInfos SignerInfos }

 */
package PKCS7;

import java.security.Certificate;
import java.security.cert.CRL;
import java.util.Set;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author joao
 */
public class SignedAndEnvelopedData {
    int version;
    Set<RecipientInfo> recipientInfos;
    AlgorithmIdentifier digestAlgorithmIdentifier;
    EncryptedContentInfo encryptedContentInfo;
    CRL certificates;
    ExtendedCertificateOrCertificate crls;
    Set<SignerInfo> signerInfos;
    
    /**
     * Basic construtor
     * @param v
     * @param ri
     * @param dai
     * @param eci
     * @param si 
     */
    public SignedAndEnvelopedData(int v, Set<RecipientInfo> ri, AlgorithmIdentifier dai, EncryptedContentInfo eci,
           Set<SignerInfo> si ){
        version = v;
        recipientInfos = ri;
        digestAlgorithmIdentifier = dai;
        encryptedContentInfo = eci;
        signerInfos = si;
    }
    
    /**
     * Optional COnstructor
     * @param v
     * @param ri
     * @param dai
     * @param eci
     * @param certs - Optional
     * @param crls - Optional
     * @param si 
     */    
    public SignedAndEnvelopedData(int v, Set<RecipientInfo> ri, AlgorithmIdentifier dai, EncryptedContentInfo eci,
           CRL certs, ExtendedCertificateOrCertificate crls, Set<SignerInfo> si ){
        version = v;
        recipientInfos = ri;
        digestAlgorithmIdentifier = dai;
        encryptedContentInfo = eci;
        certificates = certs;
        this.crls = crls;
        signerInfos = si;
    }
    
    public int getVersion(){return version;}
    public Set<RecipientInfo> getRecipientInfos(){return recipientInfos;}
    public EncryptedContentInfo getEncryptedContentInfo(){return encryptedContentInfo;}
    public CRL getCertificates(){return certificates;}
    public ExtendedCertificateOrCertificate getCRL(){return crls;}
    public Set<SignerInfo> getSignerInfos(){return signerInfos;}
    
    public String toString(){
        StringBuilder st = new StringBuilder("SignedAndEnvelopedData ::= SEQUENCE { version ");
        st.append(version+",\n");
        st.append("digestAlgorithms "+digestAlgorithmIdentifier.toString()+",\n");
        st.append(encryptedContentInfo.toString()+",\n");
        st.append("certificates "+ crls.toString() +",\n");
        st.append(signerInfos.toString());
        
        return st.toString();
    }
}
