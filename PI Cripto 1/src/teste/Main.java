package teste;

import java.util.logging.Level;
import java.util.logging.Logger;


public class Main {

    public static void main(String[] args) {

        RW_File rw = new RW_File(args[0]); // Ler o ficheiro com a mensagem

        try {

            BouncyCastle bc = new BouncyCastle(args[1]);

            System.out.println(new String(bc.sign(rw.readByteFile(), Gadgets.getPasswordFromConsole(System.console(), new char[] {'K','e','y','S','t','o','r','e',' ','P','a','s','s','w','o','r','d',':',' '}), args[2])));
        }
        catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
