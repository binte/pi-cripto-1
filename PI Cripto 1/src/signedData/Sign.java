package signedData;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


public class Sign {

    private String algorithm;   // algoritmo de assinatura de mensagem

    
    public Sign(String dgst_algorithm, String algorithm){

        if(dgst_algorithm != null)
            this.algorithm = Gadgets.concatDigestWithEncryptionAlgorithm(dgst_algorithm, algorithm);
        else
            this.algorithm = algorithm;
    }
    

    public byte[] computeSignature(byte[] message, PrivateKey key) throws Exception {

        /* Criar uma instância da classe Signature para calcular uma assinatura da mensagem
         através do algoritmo passado à instância */
        Signature sign = Signature.getInstance(algorithm);

        //Inicializar o objecto Signature com a publicKey
        sign.initSign(key);
        
        // Fornecer ao objecto Signature instanciado em cima a mensagem da qual se pretende obter uma assinatura
        sign.update(message);


        // Computar e retornar a assinatura da mensagem
        byte[] sig = sign.sign();
        
        return sig;
    }


    /**
     * Recebe mensagem e verifica a assinatura.
     *
     * @param verifyKey: Chave pública da outra parte
     * @param msg:       A mensagem que foi assinada
     * @param sign:      Assinatura gerada na outra parte e enviada para esta entidade
     * 
     * @return boolean:  Assinatura corrompida ou não
     */
    public final boolean verifySign(PublicKey verifyKey, byte[] msg, byte[] sign) throws Exception {

        // Instanciar uma Signature para um dado algoritmo de assinaturas
        Signature signature = Signature.getInstance(this.algorithm);

        // Inicializar o Objecto Signature com a chave pública da outra parte
        signature.initVerify(verifyKey);

        // Fornecer ao Objecto Signature a mensagem que foi assinada
        signature.update(msg);


        /* Executa a verificação da assinatura recebida e se esta equivaler à assinatura da mensagem recebida
         retorna true. Caso contrário retorna false */
        return signature.verify(sign);
    }
}
