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
    /**
     * Gets 
     */
    public Content getContent(){return content;}
    public AlgorithmIdentifier get(){ return contentEncryptionAlgorithm;}
    public byte[] getEncryptedContent(){return encryptedContent;}
    
    
    public String toString(){
        StringBuilder sb = new StringBuilder("EncryptedContentInfo ::= SEQUENCE {contentType ");
        sb.append(content.toString()+",\n");
        sb.append("contentEncryptionAlgorithm "+contentEncryptionAlgorithm.toString()+",\n");
        if(encryptedContent!=null) sb.append("encryptedContent "+ new String(encryptedContent.toString())+",\n");
        
        return sb.toString();
    }
}
