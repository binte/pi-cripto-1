/*
 * RecipientInfo ::= SEQUENCE { version Version,
                                issuerAndSerialNumber IssuerAndSerialNumber,
                                keyEncryptionAlgorithm
                                KeyEncryptionAlgorithmIdentifier,
                                encryptedKey EncryptedKey }

 */
package PKCS7;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author joao
 */
public class RecipientInfo {
    
    private int version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier keyAlgorithmIdentifier;
    byte[] encryptedKey;
    
    public RecipientInfo(int v,IssuerAndSerialNumber iasn, AlgorithmIdentifier kai, byte[] ek){
        version = v;
        issuerAndSerialNumber = iasn;
        keyAlgorithmIdentifier = kai;
        encryptedKey = ek;
    }
    
    /*
 * RecipientInfo ::= SEQUENCE { version Version,
                                issuerAndSerialNumber IssuerAndSerialNumber,
                                keyEncryptionAlgorithm
                                KeyEncryptionAlgorithmIdentifier,
                                encryptedKey EncryptedKey }

 */
    
    public String toString(){
        StringBuilder st = new StringBuilder("RecipientInfo ::= SEQUENCE { version");
        st.append(version+",\n");
        st.append("issuerAndSerialNumber "+issuerAndSerialNumber.toString()+",\n");
        st.append("keyEncryptionAlgorithm "+keyAlgorithmIdentifier.toString()+",\n");
        st.append("encryptedKey "+new String(encryptedKey)+",\n");
    
        return st.toString();
    }
    
}
