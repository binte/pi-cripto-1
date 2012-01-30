/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package MIMESignedData;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import signedData.Gadgets;

/**
 *
 * @author joao
 */
public class TesteMIME {
   
    public static void main(String[] args) throws MessagingException, SMIMEException, IOException{
        /*
         * args[0] - Chave privada RSA para cifrar
         */
    
        //Lêr a chave privada par assinar a mensagem SMIME 
        PrivateKey pk = null;
        try {
            pk = Gadgets.readKeyPair2(new File(args[0]));
        } catch (Exception ex) {
            Logger.getLogger(TesteMIME.class.getName()).log(Level.SEVERE, null, ex);
        }

        
        //Criar o SMIME SignedGenerator
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        
        gen.addSigner(pk, null, null);
        
        //Criar a mensagem a assinar
        MimeBodyPart msg = new MimeBodyPart();
        msg.setText("Hello world!");
        msg.addHeader("escaxe", "asf");
        
        
        MimeMultipart mm = gen.generate(msg);
        
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);
        
        MimeMessage body = new MimeMessage(session);
        body.setContent(mm, mm.getContentType());
        body.saveChanges();
        body.writeTo(new FileOutputStream("testesignedmessage"));
        
         } 
        
    }