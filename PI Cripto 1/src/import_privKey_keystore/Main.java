package import_privKey_keystore;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;


public class Main {

    /**
     * <p>Takes two file names for a key and the certificate for the key,
     * and imports those into a keystore. Optionally it takes an alias
     * for the key.
     * <p>The first argument is the filename for the key. The key should be
     * in PKCS8-format.
     * <p>The second argument is the filename for the certificate for the key.
     * <p>If a third argument is given it is used as the alias. If missing,
     * the key is imported with the alias importkey
     * <p>The name of the keystore file can be controlled by setting
     * the keystore property (java -Dkeystore=mykeystore). If no name
     * is given, the file is named <code>keystore.ImportKey</code>
     * and placed in your home directory.
     * @param args [0] Name of the key file, [1] Name of the certificate file
     * [2] Alias for the key.
     **/
    public static void main ( String args[]) {

        // change this if you want another password by default
        String keypass = "importkey";

        // change this if you want another alias by default
        String defaultKeyAlias = "importcert";

        // change this if you want another keystorefile by default
        String keystorename = System.getProperty("keystore");

        if (keystorename == null)
            keystorename = "keystore.ImportKey";


        // parsing command line input
        String keyfile = "";
        String certfile = "";
        if (args.length < 2 || args.length>5) {
            System.out.println("Usage: java comu.ImportKey keyfile certfile [key alias] [keystore] [keystore_passphrase] ");
            System.exit(0);
        } else {
            keyfile = args[0];
            certfile = args[1];
            if (args.length>2)
                defaultKeyAlias = args[2];
            if (args.length>3)
                keystorename = args[3];
            if (args.length>4)
                keypass = args[4];
        }

        try {
            // initializing and clearing keystore
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");

            try {
		ks.load(new FileInputStream ( keystorename ), keypass.toCharArray());
                System.out.println("Using keystore-file : "+keystorename);
	    } catch ( IOException e) {
                System.out.println("Creating keystore : "+keystorename);
                ks.load( null , keypass.toCharArray());
                ks.store(new FileOutputStream ( keystorename  ), keypass.toCharArray());
            }

            // loading Key
            InputStream fl = ImportKey.fullStream(keyfile);
            byte[] key = new byte[fl.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            fl.read ( key, 0, fl.available() );
            fl.close();
            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec ( key );
            PrivateKey ff = kf.generatePrivate (keysp);

            // loading CertificateChain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certstream = ImportKey.fullStream(certfile);

            Collection c = cf.generateCertificates(certstream) ;
            X509Certificate[] certs = new X509Certificate[c.toArray().length];

            if (c.size() == 1) {
                certstream = ImportKey.fullStream(certfile);
                System.out.println("One certificate, no chain.");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(certstream) ;
                certs[0] = (X509Certificate) cert;
            } else {
                System.out.println("Certificate chain length: "+c.size());
                certs = (X509Certificate[])c.toArray();
            }



            // storing keystore            
            ks.setKeyEntry(defaultKeyAlias, ff,
                           keypass.toCharArray(),(X509Certificate[]) certs);

            System.out.println ("Key and certificate stored.");
            System.out.println ("Alias:"+defaultKeyAlias+"  Password:"+keypass);
            ks.store(new FileOutputStream ( keystorename ),
                     keypass.toCharArray());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
