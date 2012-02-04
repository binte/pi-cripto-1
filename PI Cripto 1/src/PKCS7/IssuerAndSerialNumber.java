/***
 * Classe que identifica o certificado 
 * 
 * IssuerAndSerialNumber ::= SEQUENCE { Issuer issuer,
 *                                      SerialNumber serialNumber }
 */

package PKCS7;


public class IssuerAndSerialNumber {

    private String issuer;
    private String serialNumber;


    public IssuerAndSerialNumber(String issuer, String serialNumber) {

        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }


    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append("IssuerAndSerialNumber ::= SEQUENCE { Issuer " + this.issuer + ",\n");
        sb.append("SerialNumber " + this.serialNumber + " }\n");

        return sb.toString();
    }
}
