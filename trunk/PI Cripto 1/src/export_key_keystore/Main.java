package export_key_keystore;


public class Main {

    public static void main(String args[]) throws Exception{

        int flag = 0;

        // se o programa tiver recebido o número correcto de parâmetros
        if(args.length == 4) {

            if(args[0].equals("public"))
                flag = 1;
            else
                if(args[0].equals("private"))
                    flag = 2;
        }


        // se o input do programa não for o correcto
        if (flag == 0) {

                System.err.println("Usage: java -jar <jar file> <-public|-private> <keystore file> <certificate alias> <output file>");
                System.exit(1);
        }


        ExportKey.export(flag, args[1], args[2], args[3]);
    }
}
