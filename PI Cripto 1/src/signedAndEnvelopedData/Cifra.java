package signedAndEnvelopedData;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Cifra {

    private String algorithm;   // algoritmo utilizado para cifrar/decifrar
    private String keyFile;     // ficheiro no qual está contida a chave privada utilizada para cifrar/decifrar 
    private String provider;    // Provider a utilizar
    
    public Cifra(String algorithm) {

        this.algorithm = algorithm;
    }
    
    public Cifra(String algorithm , String provider){
        
        this.algorithm = algorithm;
        this.provider = provider;
    }
    

    public void setAlgorithm(String algorithm) {

        this.algorithm = algorithm;
    }

    public void setFile(String keyFile) {

        this.keyFile = keyFile;
    }

    
    /**
     * Decifrar um criptograma com uma chave privada
     *
     * @param array de bytes com o criptograma a decifrar
     *
     * @return array de bytes contendo o texto limpo equivalente à desencriptação do criptograma
     */
    public byte[] decifrar(byte[] encrypted) throws Exception{

        byte[] secret_text = null;
        File privateKey = new File(this.keyFile);
        KeyPair keyPair = Gadgets.readKeyPair(privateKey);


        /* Criar um objecto Cipher, que implemente uma dada transformação. A transformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cipher = Cipher.getInstance(this.algorithm, Security.getProvider(this.provider));

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar com a chave privada
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Decifrar o array de bytes cifrado, que recebido pela função, num único passo
        secret_text = cipher.doFinal(encrypted);

        return secret_text;
    }

    /**
     * Decifrar um criptograma com uma SecretKeySpec no modo ECB (pois não recebe IV)
     *
     * @param Chave secreta para decifrar o criptograma
     * @param Criptograma a decifrar
     *
     * @return array de bytes contendo o texto limpo equivalente à desencriptação do criptograma
     */
    public byte[] decifrar(SecretKeySpec key, byte[] criptograma) throws Exception{

        byte [] mensagem = null;


        /* Criar um objecto Cipher, que implemente uma dada transformação. A transformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cp = Cipher.getInstance(this.algorithm, Security.getProvider(this.provider));

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar com a chave privada
        cp.init(Cipher.DECRYPT_MODE, key);

        // Desencriptar o array de bytes encriptado recebido pela função num único passo
        mensagem = cp.doFinal(criptograma);

        return mensagem;
    }

    /**
     * Decifrar um criptograma com uma SecretKeySpec
     *
     * @param Chave secreta para decifrar o criptograma
     * @param Criptograma a decifrar
     * @param IV (Initialization Vector), responsável pela introdução de aleatoriedade na encriptação, é também
     * necessário para a desencriptação.
     *
     * @return array de bytes contendo o texto limpo equivalente à desencriptação do criptograma
     */
    public byte[] decifrar(SecretKeySpec key, byte[] criptograma, byte[] iv) throws Exception{

        byte [] mensagem = null;

        
        /* Criar um objecto Cipher, que implemente uma dada transformação. A transformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */
        Cipher cp = Cipher.getInstance(this.algorithm, Security.getProvider(this.provider));

        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar com a chave privada
        cp.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Desencriptar o array de bytes encriptado recebido pela função num único passo
        mensagem = cp.doFinal(criptograma);

        return mensagem;
    }

    /**
     * Decifrar um criptograma com uma chave pública
     *
     * @param Chave pública para decifrar o criptograma
     * @param Criptograma a decifrar
     *
     * @return array de bytes contendo o texto limpo equivalente à desencriptação do criptograma
     */
    public byte[] decifrar(PublicKey key, byte[] criptograma) throws Exception{
        
        byte [] mensagem = null;

        System.out.println(Gadgets.asHex(key.getEncoded()));
        
        /* Criar um objecto Cipher, que implemente uma dada transformação. A transformação é uma string na forma:

            "algoritmo/modo/padding" ou
            "algoritmo"
         */ 
        Cipher cp = Cipher.getInstance(this.algorithm, Security.getProvider(this.provider));
        
        // Inicializar o objecto do tipo Cipher criado em cima, no modo de desencriptar com a chave privada
        cp.init(Cipher.DECRYPT_MODE, key);
        
        // Desencriptar o array de bytes encriptado recebido pela função num único passo  
        mensagem = cp.doFinal(criptograma);
        
        return mensagem;
    }

    /**
     * Construir uma Secret Key através do array de bytes correspondente
     *
     * @param array de bytes contendo a chave
     *
     * @return SecretKeySpec com a especificação da chave secreta relativa ao array de bytes recebido
     */
    public SecretKeySpec build_key(byte[] key) throws Exception{

        // Cria instância duma classe que implementa as especificações duma chave secreta a partir do seu array de bytes
        return new SecretKeySpec(key, this.algorithm);
    }
}
