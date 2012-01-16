package signedAndEnvelopedData;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;


public class Certificate_Handler {

    public static boolean verifyCertificate(String CAfile, X509Certificate cert) throws Exception {

        boolean valid = false;

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

        // TrustAnchor representa os pressupostos de confiança que se aceita como válidos
        // (neste caso, unicamente a CA que emitiu os certificados)
        TrustAnchor anchor = new TrustAnchor(getCertFromFile(CAfile) , null);

        // Podemos também configurar o próprio processo de validação
        // (e.g. requerer a presença de determinada extensão).
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));

        // ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
        params.setRevocationEnabled(false);


        CertPath cp = createPath(cert);


        // Finalmente a validação propriamente dita...
        try {

            CertPathValidatorResult cpvResult = cpv.validate(cp, params);

            valid = true;

        } catch (InvalidAlgorithmParameterException iape) {

            throw new Exception("Validation error: " + iape);

        } catch (CertPathValidatorException cpve) {

            throw new Exception("Validation failure: " + cpve +"\n"+

                                "Posição do certificado causador do erro: "+ cpve.getIndex());
        }

        return valid;
    }

    public static X509Certificate getCertFromFile(String certFilePath) throws Exception {

        X509Certificate cert = null;
        File certFile = new File(certFilePath);
        FileInputStream certFileInputStream = new FileInputStream(certFile);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(certFileInputStream);

        return cert;
    }

    private static CertPath createPath(X509Certificate cert) throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ArrayList al = new ArrayList();
        al.add(cert);

        return cf.generateCertPath(al);
    }
}
