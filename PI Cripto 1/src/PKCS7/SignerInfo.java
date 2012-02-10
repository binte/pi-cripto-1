/***
 * Contém a informação do signatário.
 *
 * SignerInfo ::= SEQUENCE { version Version, 
 *                           issuerAndSerialNumber IssuerAndSerialNumber,
 *                           digestAlgorithm DigestAlgorithmIdentifier,
 *                           authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
 *                           digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *                           encryptedDigest EncryptedDigest,
 *                           unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
 */

package PKCS7;

import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import signedData.Gadgets;


public class SignerInfo {

    private int version;
    private PKCS7.IssuerAndSerialNumber isn;
    private AlgorithmIdentifier dgstAlgID;
    private Attributes authenticatedAttributes;
    private AlgorithmIdentifier dgstEncryptionAlgorithm;
    private byte[] encryptedDigest;
    private Attributes unauthenticatedAttributes;


    public SignerInfo(int version, PKCS7.IssuerAndSerialNumber isn, AlgorithmIdentifier dgstAlgID,
            Attributes authenticatedAttributes, AlgorithmIdentifier dgstEncryptionAlgorithm,
            byte[] encryptedDigest, Attributes unauthenticatedAttributes) {

        this.version = version;
        this.isn = isn;
        this.dgstAlgID = dgstAlgID;
        this.authenticatedAttributes = authenticatedAttributes;
        this.dgstEncryptionAlgorithm = dgstEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = unauthenticatedAttributes;
    }


    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append(" SignerInfo ::= SEQUENCE { Version " + this.version + ",\n");
        sb.append("                           issuerAndSerialNumber " + this.isn.toString() + ",\n");
        sb.append("                           digestAlgorithm " + signedData.SignedHelper.getDigestAlgName(this.dgstAlgID.getAlgorithm().getId()) + ",\n");

        if(this.authenticatedAttributes != null)
            sb.append("                           authenticatedAttributes " + this.authenticatedAttributes.toString() + ",\n");
        else
            sb.append("                           authenticatedAttributes: " + this.authenticatedAttributes);

        sb.append("                           digestEncryptionAlgorithm " + signedData.SignedHelper.getEncryptionAlgName(this.dgstEncryptionAlgorithm.getAlgorithm().getId()) + ",\n");
        sb.append("                           encryptedDigest: ******,\n");

        if(this.unauthenticatedAttributes != null)
            sb.append("                           unauthenticatedAttributes: " + this.unauthenticatedAttributes.toString());
        else
            sb.append("                           unauthenticatedAttributes: " + this.unauthenticatedAttributes);

        sb.append(" }\n");

        return sb.toString();
    }
}
