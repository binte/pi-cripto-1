/*
 * * Contem a informação do conteúdo cifrado
 * 
 *              EncryptedData ::= SEQUENCE { version Version,
 *                                           encryptedContentInfo EncryptedContentInfo }
 *
 */
package PKCS7;

import java.util.Set;
import javax.mail.internet.MimePart;
import org.bouncycastle.asn1.cms.RecipientInfo;


/**
 *
 * @author joao
 */
public class EncryptedData extends Content{
    
    private int version;
    private EncryptedContentInfo encryptedContentInfo;
    
    //Opcional
    private String unprotectredAttrs;
    
    /**
     * Basic Constructor
     * @param version
     * @param eci 
     */
    public EncryptedData(int version,EncryptedContentInfo eci){
        
        super(version);
        encryptedContentInfo = eci;
    }
    
    /**
     * Optional Constructor
     * @param version
     * @param attrs - Optional
     * @param eci 
     */
    public EncryptedData(int version,String attrs,EncryptedContentInfo eci){

        super(version);
        unprotectredAttrs = attrs;
        encryptedContentInfo = eci;
    }
    
    public int getVersion(){return version;}
    public EncryptedContentInfo getEncryptedContentInfo(){return encryptedContentInfo;}
    public String getUnprotectedAttributes(){return unprotectredAttrs;}
            
    public String toString(){
        
        StringBuilder st = new StringBuilder("EncryptedData ::= SEQUENCE { version");
        st.append(version+",\n");
        st.append(encryptedContentInfo.toString());
        return st.toString();
    }
}
