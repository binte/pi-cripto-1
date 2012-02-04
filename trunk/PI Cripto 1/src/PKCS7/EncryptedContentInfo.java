/*
 * 
 * EncryptedContentInfo ::= SEQUENCE {contentType ContentType,
                                      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
                                      encryptedContent
                                        [0] IMPLICIT EncryptedContent OPTIONAL }
   EncryptedContent ::= OCTET STRING

 */
package PKCS7;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author joao
 */
public class EncryptedContentInfo {

    private Content content;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private byte[] encryptedContent;
    
    /**
     * Basic Constructor
     * @param content
     * @param ai 
     */
    public EncryptedContentInfo(Content content, AlgorithmIdentifier ai){
        this.content = content;
        contentEncryptionAlgorithm = ai;
    }
    
    /**
     * Optional Constructor
     * @param content
     * @param ai
     * @param ec - Optional
     */
    public EncryptedContentInfo(Content content, AlgorithmIdentifier ai, byte[] ec){
        this.content = content;
        contentEncryptionAlgorithm = ai;
        encryptedContent = ec;
    }
}
