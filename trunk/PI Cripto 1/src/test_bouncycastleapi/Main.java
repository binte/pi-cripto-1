/*
 * Classe que testa se a API BouncyCastle está instalada, imprimindo uma mensagem com o resultado da operação
 */

package test_bouncycastleapi;

import java.security.Security;

public class Main {
    
    public static void main(String[] args) {
        
        //BC is the ID for the Bouncy Castle provider;
        if (Security.getProvider("BC") == null) {

            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{

            System.out.println("Bouncy Castle provider is available");
        }
    }
}

