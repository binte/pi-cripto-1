/**
 * Estrutura principal de um pacote Signed Data.
 * 
 * SignedData ::= SEQUENCE { version Version,
 *                           digestAlgorithms DigestAlgorithmIdentifiers,
 *                           contentInfo ContentInfo,
 *                           certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *                           crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *                           signerInfos SignerInfos }
 */

package PKCS7;

import java.security.cert.CRL;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class SignedData extends Content {

    private int version;
    private AlgorithmIdentifier algID;
    private AlgorithmIdentifier dgstAlgID;
    private ContentInfo contentInfo;
    private ExtendedCertificateOrCertificate certificate;
    private CRL crl;
    private SignerInfo signerInfo;

    
    public SignedData(int version, AlgorithmIdentifier algID, AlgorithmIdentifier dgstAlgID, ContentInfo contentInfo, SignerInfo signerInfo) {

        super(version);
        this.algID = algID;
        this.dgstAlgID = dgstAlgID;
        this.contentInfo = contentInfo;
        this.signerInfo = signerInfo;
    }


    
}
