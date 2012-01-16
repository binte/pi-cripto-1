package signedAndEnvelopedData;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;


public class Main {

    public static void main(String[] args) {

        String sym_algorithm = "AES/CBC/PKCS7Padding", asym_algorithm = "RSA", provider = "BC",
                digest_algorithm = "SHA-256";
        byte[] encrypted, decrypted, decrypted_digest, computed_digest, iv, tmp;
        Cifra cipher = new Cifra(asym_algorithm, provider);
        Digest dgst = new Digest(digest_algorithm, 32);
        RW_File rw;
        X509Certificate cert;
        SecretKeySpec skey;
        

        // Se tiverem sido passados dois parâmetros ao programa
        if( args.length == 8) {

            /**
             * 0 - Path do ficheiro que contém o certificado da CA (formato DER)
             * 1 - Path do ficheiro que contém o certificado do emissor (formato DER)
             * 2 - Path do ficheiro que contém a assinatura (duplamente) encriptada
             * 3 - Path do ficheiro no qual está contida a chave secreta encriptada
             * 4 - Path do ficheiro que contém o par de chaves do receptor em formato PEM
             * 5 - Path do ficheiro que contém o criptograma
             * 6 - Path do ficheiro que contém o par de chaves do emissor em formato PEM
             * 7 - Path do ficheiro onde está o IV
             */


            try {
                
                /*************************************/
                /* Receber o Certificado do Emissor */
                /*************************************/
                

                /* Criar um objecto com o Certificado do Emissor */
                cert = Certificate_Handler.getCertFromFile(args[1]);
                
                /* Verificar o certificado do emissor com a CA */
                if(Certificate_Handler.verifyCertificate(args[0], cert)) {



                    /************************************/
                    /* Enviar o Certificado ao emissor */
                    /************************************/
                    

                    
//PASSO 13
                    rw = new RW_File(args[3]);

                    // ler os bytes do ficheiro que contém a chave secreta encriptada
                    encrypted = rw.readByteFile();

                    // especificar o ficheiro no qual está contida a chave privada que irá ser utilizada para decifrar
                    cipher.setFile(args[4]);  // a chave secreta

                    // desencriptar a chave secreta
                    decrypted = cipher.decifrar(encrypted);

                    /* obter a SecretKey através do criptograma desencriptado (antes é necessário mudar o algoritmo
                    da cifra para o algoritmo simétrico correspondente à chave desencriptada) */
                    cipher.setAlgorithm(sym_algorithm);
                    skey = cipher.build_key(Gadgets.hexStringToByteArray(new String(decrypted)));
                    


// PASSO 14
                    rw = new RW_File(args[5]);

                    // ler os bytes do ficheiro que contém o criptograma
                    encrypted = rw.readByteFile();

                    rw = new RW_File(args[7]);

                    // ler os bytes do ficheiro que contém o IV
                    iv = rw.readByteFile();

                    // desencriptar o criptograma
                    decrypted = cipher.decifrar(skey, encrypted, Gadgets.hexStringToByteArray(new String(iv)));



// PASSO 15
                    rw = new RW_File(args[2]);

                    // ler os bytes do ficheiro que contém a assinatura duplamente encriptada
                    encrypted = rw.readByteFile();

                    // desencriptar a assinatura através do mesmo algoritmo simétrico
                    tmp = cipher.decifrar(skey, encrypted, Gadgets.hexStringToByteArray(new String(iv)));


                    
// PASSO 16
                    /* desencriptar o resultado do passo anterior com o algoritmo assimétrico utilizado, 
                     de forma a obter o resumo da mensagem */
                    cipher.setAlgorithm(asym_algorithm);
                    decrypted_digest = cipher.decifrar(Gadgets.readKeyPair(new File(args[6])).getPublic(), tmp);


                    
// PASSO 17
                    // computar o resumo da mensagem da mensagem desencriptada
                    computed_digest = dgst.computeMessageDigest(decrypted);



// PASSO 18
                    /* Comparar o resumo da mensagem com o resumo de mensagem desencriptado em cima */
                    if( MessageDigest.isEqual(decrypted_digest, computed_digest) )
                        System.out.println("check");
                    else
                        System.out.println("fail");
                }
                else
                    throw new Exception("Invalid Certificate");
            }
            catch (Exception ex) {

                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
            System.err.println("Invalid parameter number: " + args.length);
    }
}
