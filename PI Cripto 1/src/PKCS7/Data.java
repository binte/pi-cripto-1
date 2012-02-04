/**
 * Data ::= OCTET STRING
 */

package PKCS7;

public class Data {


    private byte[] data;


    public Data(byte[] data) {

        this.data = data;
    }


    /***
     * Retorna a mensagem em claro
     *
     * @return String
     */
    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append("Data ::= " + new String(this.data) + "\n");

        return sb.toString();
    }
}
