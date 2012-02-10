package signedData;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.*;


public class Cifra {

    private String algorithm;   // algoritmo utilizado para cifrar/decifrar
    private String provider;    // nome do provider utilizado


    public Cifra(String algorithm, String provider) {

        this.algorithm = algorithm;
        this.provider = provider;
    }
    

    /**
     * Dada uma chave privada, desencriptar o criptograma
     *
     * @param byte[] contendo o criptograma
     * @param PrivateKey com a chave privada
     *
     * @return byte[] com a mensagem original
     */
    public byte[] decifrar(byte[] encrypted, PrivateKey privateKey) throws Exception{

        byte[] secret_text = null;

        /* Criar um objecto Cipher, que implemente uma dada transformação. A tranformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cipher = Cipher.getInstance(this.algorithm, this.provider);

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Desencriptar o array de bytes encriptado recebido pela função num único passo
        secret_text = cipher.doFinal(encrypted);

        return secret_text;
    }

    /**
     * Dada uma chave privada, desencriptar o criptograma
     *
     * @param byte[] contendo o criptograma
     * @param PrivateKey com a chave privada
     *
     * @return byte[] com a mensagem original
     */
    public byte[] decifrar(byte[] encrypted, PublicKey pubKey) throws Exception{

        byte[] secret_text = null;

        /* Criar um objecto Cipher, que implemente uma dada transformação. A tranformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cipher = Cipher.getInstance(this.algorithm);

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar
        cipher.init(Cipher.DECRYPT_MODE, pubKey);

        // Desencriptar o array de bytes encriptado recebido pela função num único passo
        secret_text = cipher.doFinal(encrypted);

        return secret_text;
    }
    
    public byte[] decifrar(byte[] encrypted, SecretKey sKey) throws Exception{

        byte[] secret_text = null;

        /* Criar um objecto Cipher, que implemente uma dada transformação. A tranformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cipher = Cipher.getInstance(this.algorithm);

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar
        cipher.init(Cipher.DECRYPT_MODE, sKey);

        // Desencriptar o array de bytes encriptado recebido pela função num único passo
        secret_text = cipher.doFinal(encrypted);

        return secret_text;
    }
}
