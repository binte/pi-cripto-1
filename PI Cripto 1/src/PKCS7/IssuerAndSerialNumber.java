/***
 * Classe que identifica o certificado 
 * 
 * IssuerAndSerialNumber ::= SEQUENCE { Issuer issuer,
 *                                      SerialNumber serialNumber }
 */

package PKCS7;

import javax.security.auth.x500.X500Principal;
import sun.security.x509.CertificateSerialNumber;


public class IssuerAndSerialNumber {

    private X500Principal issuer;
    private CertificateSerialNumber serialNumber;


    public IssuerAndSerialNumber(X500Principal issuer, CertificateSerialNumber serialNumber) {

        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }
    
    /**
     * Gets
     * @return 
     */
    public X500Principal getIssuer(){return issuer;}
    public CertificateSerialNumber getSerialNumber(){return serialNumber;}

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append("IssuerAndSerialNumber ::= SEQUENCE { Issuer " + this.issuer.toString() + ", ");
        sb.append("SerialNumber " + this.serialNumber.toString() + " }");

        return sb.toString();
    }
}
