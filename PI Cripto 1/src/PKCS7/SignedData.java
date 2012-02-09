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
import java.util.Collection;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class SignedData extends Content {

    private int version;
    private Collection<AlgorithmIdentifier> dgstAlgID;
    private ContentInfo contentInfo;
    private ExtendedCertificateOrCertificate certificate;
    private CRL crl;
    private Collection<SignerInfo> signerInfos;

    
    public SignedData(int version, ContentInfo contentInfo, Collection<SignerInfo> signerInfos) {

        super(version);
        this.dgstAlgID = null;
        this.contentInfo = contentInfo;
        this.signerInfos = signerInfos;
    }


    
}
