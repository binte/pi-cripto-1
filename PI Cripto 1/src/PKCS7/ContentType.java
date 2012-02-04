/***
 * Identifica o tipo de objecto, podendo ser um dos seguintes tipos de objectos Content:
 * 
 * data -> data OBJECT IDENTIFIER ::= { pkcs-7 1 }
 * signedData -> signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
 * envelopedData -> envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
 * signedAndEnvelopedData -> signedAndEnvelopedData OBJECT IDENTIFIER ::= { pkcs-7 4 }
 * digestedData -> digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
 * encryptedData -> encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }
 */

package PKCS7;

import java.util.StringTokenizer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import signedData.Gadgets;


public class ContentType {

    ASN1ObjectIdentifier objID;


    public ContentType(ASN1ObjectIdentifier objID) {

        this.objID = objID;
    }


    /**
     * retorna o OID do contentType
     *
     * @return String com o OID do contentType
     */
    public String getContentType() {

        return Gadgets.getContentType(this.objID.toString());
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder(this.objID.toString());
        StringTokenizer st = new StringTokenizer(sb.reverse().toString());

        return "OBJECT IDENTIFIER ::= { pkcs-7 " + st.nextToken(".") + " }";
    }
}
