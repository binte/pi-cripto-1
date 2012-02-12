/***
 * Contém o algoritmo de resumo de mensagem utilizado e o resumo de mensagem computado
 *
 * DigestInfo ::= SEQUENCE { digestAlgorithm DigestAlgorithmIdentifier,
 *                           digest Digest }
 */

package PKCS7;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;



public class DigestInfo extends ASN1Encodable {

    private AlgorithmIdentifier dgstAlgID;
    private byte[] digest;


    public DigestInfo(AlgorithmIdentifier dgstAlgID, byte[] digest) {

        this.dgstAlgID = dgstAlgID;
        this.digest = digest;
    }
    
    /**
     * Gets
     * @return 
     */    
    public AlgorithmIdentifier getAlgorithmIdentifier(){return dgstAlgID;}
    public byte[] getDigest(){return digest;}
    
    

    /***
     * Método auxiliar necessário para invocar o getEncoded(), que é extendido pela classe ASN1Encodable
     *
     * @return DERObject
     */
    @Override
    public DERObject toASN1Object() {

        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(this.dgstAlgID);
        v.add(new DEROctetString(this.digest));

        return new DERSequence(v);
    }
    
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append(this.dgstAlgID.toString() + "\n");

        sb.append(this.digest.toString());

        return sb.toString();
    }
}
