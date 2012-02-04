/***
 * Classe que serve de molde para os vários tipos de Content, nomeadamente: data
 *                                                                          signedData
 *                                                                          envelopedData
 *                                                                          signedAndEnvelopedData
 *                                                                          digestedData
 *                                                                          encryptedData
 */

package PKCS7;


public class Content {

    private int version;


    public Content(int version) {

        this.version = version;
    }


    /***
     * Retorna a versão do standard PKCS7 utilizada
     *
     * @return int
     */
    public int getVersion() {

        return this.version;
    }
}
