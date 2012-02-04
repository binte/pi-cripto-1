/***
 * Classe que identifica o certificado 
 * 
 * IssuerAndSerialNumber ::= SEQUENCE { issuer,
 *                                      serialNumber }
 */

package PKCS7;


public class IssuerAndSerialNumber {

    private String issuer;
    private String serialNumber;


    public IssuerAndSerialNumber(String issuer, String serialNumber) {

        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }
}
