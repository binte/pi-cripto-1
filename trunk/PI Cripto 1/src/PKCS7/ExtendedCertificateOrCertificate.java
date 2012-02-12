/**
 * Certificado extendido
 *
 * ExtendedCertificateOrCertificate ::= CHOICE { certificate X509Certificate,
 *                                               extendedCertificate [0] IMPLICIT ExtendedCertificate }
 */

package PKCS7;

import java.security.cert.X509Certificate;


public class ExtendedCertificateOrCertificate {

    X509Certificate certificate;


    public ExtendedCertificateOrCertificate(X509Certificate certificate) {

        this.certificate = certificate;
    }
    
    public X509Certificate getExtendedCertificate(){return certificate;}
}
