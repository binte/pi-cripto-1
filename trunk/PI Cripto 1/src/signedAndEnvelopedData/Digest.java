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

package signedAndEnvelopedData;

import java.security.MessageDigest;


public class Digest {

    private String algorithm;   // algoritmo de resumo de mensagem
    private int length;         // tamanho (em bits) do array associado à geração dum MessageDigest com o algoritmo dado


    public Digest(String algorithm, int length){

        this.algorithm = algorithm;
        this.length = length;
    }


    public int getLength() {

        return this.length;
    }


    public byte[] computeMessageDigest(byte[] message) throws Exception {

        /* Criar uma instância da classe Message Digest para calcular um resumo de uma mensagem
         através do algoritmo passado à instância */
        MessageDigest dgst = MessageDigest.getInstance(this.algorithm);
        
        // Fornecer ao objecto Message Digest instanciado em cima a mensagem da qual se pretende obter um resumo
        dgst.update(message);

        // Computar e retornar o resumo da mensagem
        return dgst.digest();
    }
}
