package signedData;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;


public class RW_File {

    private String file;
    

    public RW_File(String file){

        this.file = file;
    }


    public void setFile(String file){

        this.file=file;
    }


    /**
     * Ler um ficheiro de bytes e retorná-los
     *
     * @return byte[] contendo o array de bytes lido do ficheiro
     */
    public byte[] readByteFile() throws java.io.IOException{
        
        byte[] buffer = new byte[(int) new File(this.file).length()];
        BufferedInputStream in = null;

        try {
            in = new BufferedInputStream(new FileInputStream(this.file));
            in.read(buffer);
        }
        finally {

            if (in != null)
                try {
                    in.close();
                }
                catch (IOException ignored) { }
        }
        
        return buffer;
    }

    /**
     * Escrever um array de bytes em ficheiro, nesse mesmo formato
     *
     * @param array de bytes que se pretende escrever em ficheiro
     */
    public void writeFile(byte[] code) throws FileNotFoundException, IOException{

        OutputStream out = new FileOutputStream(this.file);
        out.write(code);
        out.close();
    }

    /**
     * Escrever uma String em ficheiro, nesse mesmo formato
     *
     * @param String que se pretende escrever em ficheiro
     */
    public void writeFile(String str) throws FileNotFoundException, IOException {
        
        BufferedWriter out = new BufferedWriter(new FileWriter(this.file));
        out.write(str);
        out.close();
    }
}
