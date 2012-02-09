 /**
  * Algoritmos de funções de hash criptográficas utilizados para gerar resumos de mensagens. É também apresentado o
  * respectivo tamanho do array de bits gerado pela aplicação destes algoritmos (output array).
  *
  * MD2 - 128
  * MD4 - 128
  * MD5 - 128
  * SHA-0 - 160
  * SHA-1 - 160
  * SHA-256 - 256
  * SHA-512 - 512
  *
 **/

package signedData;

import java.security.MessageDigest;


public class Digest {

    private String algorithm;   // algoritmo de resumo de mensagem
    private int length;         // tamanho (em bits) do array associado à geração dum MessageDigest com o algoritmo dado
    private String provider;    // nome do provider utilizado


    public Digest(String algorithm, int length, String provider){

        this.algorithm = algorithm;
        this.length = length;
        this.provider = provider;
    }

    public Digest(String algorithm, String provider) {

        this.algorithm = algorithm;
        this.length = -1;
        this.provider = provider;
    }


    public String getAlgorithm() {

        return this.algorithm;
    }

    public int getLength() {

        return this.length;
    }


    /**
     * Calcular um resumo de uma mensagem
     *
     * @param byte[] com a mensagem
     *
     * @return byte[] contendo um resumo da mensagem recebida, para o algoritmo especificado na instância
     */
    public byte[] computeMessageDigest(byte[] message) throws Exception {

        /* Criar uma instância da classe Message Digest para calcular um resumo de uma mensagem
         através do algoritmo passado à instância */
        MessageDigest dgst = MessageDigest.getInstance(this.algorithm, this.provider);

        // Se ao criar um objecto desta classe não for especificado o tamanho do algoritmo, 
        if(this.length == -1)  // modificar ao instanciar um MessageDigest
            this.length = dgst.getDigestLength();

        // Fornecer ao objecto Message Digest instanciado em cima a mensagem da qual se pretende obter um resumo
        dgst.update(message);

        // Computar e retornar o resumo da mensagem
        return dgst.digest();
    }
}
