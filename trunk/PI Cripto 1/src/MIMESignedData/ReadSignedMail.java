/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package MIMESignedData;

/**
 *
 * @author joao
 */
import java.io.FileInputStream;
        import java.security.cert.CertStore;
        import java.security.cert.X509Certificate;
        import java.util.Collection;
        import java.util.Iterator;
        import java.util.Properties;

        import javax.mail.BodyPart;
        import javax.mail.Multipart;
        import javax.mail.Session;
        import javax.mail.internet.MimeBodyPart;
        import javax.mail.internet.MimeMessage;
        import javax.mail.internet.MimeMultipart;

        import org.bouncycastle.cms.SignerInformation;
        import org.bouncycastle.cms.SignerInformationStore;
        import org.bouncycastle.mail.smime.SMIMESigned;

        /**
         * a simple example that reads a basic SMIME signed mail file.
         */
        public class ReadSignedMail {
            /**
             * verify the signature (assuming the cert is contained in the message)
             */
            private static void verify(SMIMESigned s) throws Exception {
                //
                // extract the information to verify the signatures.
                //

                //
                // certificates and crls passed in the signature
                //
                CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");

                //
                // SignerInfo blocks which contain the signatures
                //
                SignerInformationStore signers = s.getSignerInfos();

                Collection c = signers.getSigners();
                Iterator it = c.iterator();

                //
                // check each signer
                //
                while (it.hasNext()) {
                    SignerInformation signer = (SignerInformation) it.next();
                    Collection certCollection = certs.getCertificates(signer
                            .getSID());

                    Iterator certIt = certCollection.iterator();
                    X509Certificate cert = (X509Certificate) certIt.next();

                    //
                    // verify that the sig is correct and that it was generated
                    // when the certificate was current
                    //
                    if (signer.verify(cert, "BC")) {
                        System.out.println("signature verified");
                    } else {
                        System.out.println("signature failed!");
                    }
                }
            }

            public static void main(String[] args) throws Exception {
                //
                // Get a Session object with the default properties.
                //         
                Properties props = System.getProperties();

                Session session = Session.getDefaultInstance(props, null);

                MimeMessage msg = new MimeMessage(session, new FileInputStream(
                        "signed.message"));

                //
                // make sure this was a multipart/signed message - there should be
                // two parts as we have one part for the content that was signed and
                // one part for the actual signature.
                //
                if (msg.isMimeType("multipart/signed")) {
                    SMIMESigned s = new SMIMESigned((MimeMultipart) msg
                            .getContent());

                    //
                    // extract the content
                    //
                    MimeBodyPart content = s.getContent();

                    System.out.println("Content:");

                    Object cont = content.getContent();
                    
                    System.out.println(content.getContentType());

                    if (cont instanceof  String) {
                        System.out.println((String) cont);
                    } else if (cont instanceof  Multipart) {
                        Multipart mp = (Multipart) cont;
                        int count = mp.getCount();
                        for (int i = 0; i < count; i++) {
                            BodyPart m = mp.getBodyPart(i);
                            Object part = m.getContent();

                            System.out.println("Part " + i);
                            System.out.println("---------------------------");

                            if (part instanceof  String) {
                                System.out.println((String) part);
                            } else {
                                System.out.println("can't print...");
                            }
                        }
                    }

                    System.out.println("Status:");

                    verify(s);
                } else if (msg.isMimeType("application/pkcs7-mime")
                        || msg.isMimeType("application/x-pkcs7-mime")) {
                    //
                    // in this case the content is wrapped in the signature block.
                    //
                    SMIMESigned s = new SMIMESigned(msg);

                    //
                    // extract the content
                    //
                    MimeBodyPart content = s.getContent();

                    System.out.println("Content:");

                    Object cont = content.getContent();

                    if (cont instanceof  String) {
                        System.out.println((String) cont);
                    }

                    System.out.println("Status:");

                    verify(s);
                } else {
                    System.err.println("Not a signed message!");
                }
            }
        }