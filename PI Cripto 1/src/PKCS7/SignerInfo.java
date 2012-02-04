/***
 * Contém a informação do signatário.
 *
 * SignerInfo ::= SEQUENCE { version Version, 
 *                           issuerAndSerialNumber IssuerAndSerialNumber,
 *                           digestAlgorithm DigestAlgorithmIdentifier,
 *                           authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
 *                           digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *                           encryptedDigest EncryptedDigest, unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL }
 */

package PKCS7;

import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class SignerInfo {

    private int version;
    private IssuerAndSerialNumber isn;
    private AlgorithmIdentifier dgstAlgID;
    private Attributes authenticatedAttributes;
    private AlgorithmIdentifier dgstEncryptionAlgorithm;
    private byte[] encryptedDigest;
    private Attributes unauthenticatedAttributes;


    public SignerInfo(int version, IssuerAndSerialNumber isn, AlgorithmIdentifier dgstAlgID,
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
}
