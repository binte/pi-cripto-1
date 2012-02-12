package smimeReader;

import org.bouncycastle.openssl.PasswordFinder;


public class Password implements PasswordFinder {

    private String password;

    
    public Password(String password){

        this.password = password;
    }

    
    public char[] getPassword() {

        return password.toCharArray();
    }
}
