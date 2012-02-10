package SignatureCalculator;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import signedData.Gadgets;
import signedData.RW_File;
import signedData.Sign;


public class Main {

    public static void main(String[] args) {

        Sign sig;
        Properties props;
        Session session;
        MimeMessage msg;
        SMIMESigned signed;
        SignerInformation s;
        SignerInformationStore signers;


        
        // Se tiver sido passado um parâmetro ao programa
        if( args.length == 1) {

            try {
                
                props = System.getProperties();
                session = Session.getDefaultInstance(props);

                msg = new MimeMessage(session, new FileInputStream(args[0]));
                signed = new SMIMESigned((MimeMultipart) msg.getContent());




                /* Iterar os signatários */
                signers = signed.getSignerInfos();
                Collection c = signers.getSigners();
                Iterator it = c.iterator();


                /* Isolar a informação do signatário */
                s = (SignerInformation) it.next();

                
                sig = new Sign(signedData.SignedHelper.getDigestAlgName(s.getDigestAlgOID()), signedData.SignedHelper.getEncryptionAlgName(s.getEncryptionAlgOID()), "BC");

RW_File rw = new RW_File("Signer/message.txt");
KeyPair kp = Gadgets.readKeyPair(new File("Signer/signer_key.pem"));
byte[] teste = sig.computeSignature(rw.readByteFile(), kp.getPrivate());
rw.setFile("sig_output.hex");


//                KeyPair kp = Gadgets.readKeyPair(new File("Signer/signer_key.pem"));
//                byte[] teste = sig.computeSignature(((String)signed.getContent().getContent()).getBytes(), kp.getPrivate());




//                RW_File rw = new RW_File("sig_Output.64");
                rw.writeFile(Gadgets.asHex(teste));
            }
            catch (Exception ex) {

                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}