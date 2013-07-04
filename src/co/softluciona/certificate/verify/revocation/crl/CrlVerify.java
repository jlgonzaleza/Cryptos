/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify.revocation.crl;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.utils.Utilities;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;

/**
 *
 * @author user
 */
public class CrlVerify {

    public static final String CRL_EXT = ".crl";
    private static String pathCrl;

    
    public static void verifyRevocation(X509Certificate cert, Calendar calendar,String pathCrl_, String commonName) throws VerifyCertificateException{
        pathCrl = pathCrl_;
       X509CRL crl =loadCrl(commonName);
       verifyCrlExpireDate(crl, calendar);
       verifyCertificateAgainsCrl(crl, cert, calendar);
    }
    
    private static X509CRL loadCrl(String commonName) throws VerifyCertificateException {
        File crlFile = new File(pathCrl);
        File[] crls;
        if (pathCrl.endsWith(CRL_EXT)) {
            File[] crlsFiles = {crlFile};
            crls = crlsFiles;
        } else {
            crls = crlFile.listFiles();
        }

        if (crls == null || crls.length == 0) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.crl.files.found") + " " + pathCrl);
        }

        for (File crl : crls) {
            if (crl.isFile()) {
                FileInputStream fis;
                try {
                    fis = new FileInputStream(crl);
                } catch (FileNotFoundException ex) {
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("file.not.found") + " " + crl.getAbsolutePath());
                }
                // CRL creation
                X509CRL crlAux = null;
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crlAux = (X509CRL) cf.generateCRL(fis);
                    String[] CRLIssuerDN = crlAux.getIssuerDN().getName()
                            .split(",");
                    for (int j = 0; j < CRLIssuerDN.length; j++) {
                        if (CRLIssuerDN[j].trim().startsWith("CN=")) {
                            if (CRLIssuerDN[j].substring(3).trim().equals(commonName)) {
                                return crlAux;
                            }
                        }
                    }
                    fis.close();
                } catch (Exception e) {
                }
            }
        }
        throw new VerifyCertificateException(VerifyCertificateException.getMessage("crl.not.found"));
    }

    private static void verifyCrlExpireDate(X509CRL crl, Calendar calendar) throws VerifyCertificateException {
        if (crl.getNextUpdate().compareTo(calendar.getTime()) <= 0) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("crl.expired")+ Utilities.formatDate(crl.getNextUpdate()));
        }
    }

    private static void verifyCertificateAgainsCrl(X509CRL crl, X509Certificate cert, Calendar calendar) throws VerifyCertificateException {
       
            X509CRLEntry crlentry = crl.getRevokedCertificate(cert);
            if (crlentry != null && calendar.getTime().after(crlentry.getRevocationDate())) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.annulled")+ Utilities.formatDate(crlentry.getRevocationDate()));
            }
    }
}
