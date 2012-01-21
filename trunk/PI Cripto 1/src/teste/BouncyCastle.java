package teste;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author binte
 */
public class BouncyCastle {

    private PrivateKey privateKey;
    private String alias;


    public BouncyCastle(String alias) {

        this.alias = alias;
    }


    public static void read(byte[] signedBytes) throws Exception {

        CMSSignedData s = new CMSSignedData(signedBytes);
        CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");
        SignerInformationStore signers = s.getSignerInfos();
        boolean verified = false;
        

        for (Iterator i = signers.getSigners().iterator(); i.hasNext(); ) {
            
          SignerInformation signer = (SignerInformation) i.next();
          Collection<? extends X509Certificate> certCollection = (Collection<? extends X509Certificate>) certs.getCertificates(signer.getSID());

          if (!certCollection.isEmpty()) {
            X509Certificate cert = (X509Certificate) certCollection.iterator().next();

            if (signer.verify(cert.getPublicKey(), "BC")) {
              verified = true;
            }
          }
        }
        
        CMSProcessable signedContent = s.getSignedContent() ;
        byte[] originalContent  = (byte[]) signedContent.getContent();

        System.out.println(new String(originalContent));
    }

    public byte[] sign(byte[] data, char[] password, String path) throws Exception {
        
      Security.addProvider(new BouncyCastleProvider());
      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
      
      generator.addSigner(getPrivateKey(password, path), RW_KeyStore.getCertificate(path, "JCEKS", this.alias), CMSSignedDataGenerator.DIGEST_SHA1);
      generator.addCertificatesAndCRLs(getCertStore(password, path));
      CMSProcessable content = new CMSProcessableByteArray(data);

      CMSSignedData signedData = generator.generate(content, true, "BC");

      return signedData.getEncoded();
    }

    private CertStore getCertStore(char[] password, String path) throws Exception {

        MyKeyStoreProvider keystore = new MyKeyStoreProvider();

      ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
      X509Certificate[] certificates = (X509Certificate[]) keystore.getKeystore(password, path).getCertificateChain(this.alias);

      for (int i = 0, length = certificates == null ? 0 : certificates.length; i < length; i++)
          list.add(certificates[i]);
      
      return CertStore.getInstance("Collection", new CollectionCertStoreParameters(list), "BC");
    }

    private PrivateKey getPrivateKey(char[] password, String path) throws Exception {

        if (this.privateKey == null)
         this.privateKey = RW_KeyStore.getPrivateKey(path, "JCEKS", this.alias);

        return this.privateKey;
    }

    private PrivateKey initalizePrivateKey(char[] password, String path) throws Exception {

        KeyStore keystore = MyKeyStoreProvider.getKeystore(password, path);

        return (PrivateKey) keystore.getKey(this.alias, password);
    }
 }

