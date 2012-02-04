package PKCS7;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class SignedData extends Content {

    private int version;
    private AlgorithmIdentifier algID;
    private AlgorithmIdentifier dgstAlgID;
    private ContentInfo contentInfo;

    
    public SignedData(int version, AlgorithmIdentifier algID, AlgorithmIdentifier dgstAlgID, ContentInfo contentInfo) {

        super(version);
        this.algID = algID;
        this.dgstAlgID = dgstAlgID;
        this.contentInfo = contentInfo;
    }


    
}
