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
    private Collection<AlgorithmIdentifier> dgstAlgIDs;
    private ContentInfo contentInfo;
    private Collection<ExtendedCertificateOrCertificate> certificates;
    private Collection<CRL> crls;
    private Collection<PKCS7.SignerInfo> signerInfos;

    
    public SignedData(int version, /*Collection<AlgorithmIdentifier> dgstAlgIDs,*/ ContentInfo contentInfo, Collection<PKCS7.SignerInfo> signerInfos) {

        super(version);
        this.dgstAlgIDs = null;
        this.contentInfo = contentInfo;
        this.certificates = null;
        this.crls = null;
        this.signerInfos = signerInfos;
    }


    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append("SignedData ::= SEQUENCE { version " + this.version + ",\n");
        sb.append("                          digestAlgorithms " + this.dgstAlgIDs/*.toString()*/ + ",\n");
        sb.append("                          contentInfo " + this.contentInfo.toString() + ",\n");
        sb.append("                          certificates " + this.certificates + ",\n");
        sb.append("                          crls " + this.crls + ",\n");
        sb.append("                          signerInfos: " + this.signerInfos.size() + "\n\n");

        for(PKCS7.SignerInfo signer : this.signerInfos) {

            sb.append(signer.toString() + "\n");
        }

        sb.append("                        }");

        return sb.toString();
    }
}
