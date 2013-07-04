/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.certificate.CertificateInfo;
import co.softluciona.certificate.verify.revocation.RevocationProperties;
import co.softluciona.certificate.verify.revocation.RevocationProperties.RevocationType;
import co.softluciona.certificate.verify.revocation.crl.CrlVerify;
import co.softluciona.certificate.verify.revocation.ocsp.OcspClient;
import co.softluciona.certificate.verify.revocation.ocsp.OcspResponse;
import co.softluciona.utils.Utilities;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author user
 */
public abstract class CertificateVerify {

    protected CertificateInfo certInfo;
    private RevocationProperties revocation;
    private KeyStore caKeystore;

    public CertificateVerify(RevocationProperties revocation) throws VerifyCertificateException {
        if (revocation == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.revocation"));
        } else {
            this.revocation = revocation;
        }
    }

    protected abstract void validate() throws VerifyCertificateException;

    public CertificateInfo getCertificateInfo() {
        return this.certInfo;
    }

    public final CertificateInfo getVerifyAllCertificate() throws VerifyCertificateException {
        verifyExpiredDate();
        X509Certificate issuer = verifyTrust();
        verifyRevocation(issuer);
        return certInfo;
    }

    public final X509Certificate verifyTrust() throws VerifyCertificateException {
        return loadCA(this.certInfo.getInfoIssuer().get("CN"));
    }

    public final void verifyRevocation(X509Certificate issuer) throws VerifyCertificateException {
        if (revocation.getType().equals(RevocationType.CRL)) {
            CrlVerify.verifyRevocation(this.certInfo.getCertificateX509(), revocation.getDateToVerify(), revocation.getPathCrl(), this.certInfo.getInfoIssuer().get("CN"));
        } else if (revocation.getType().equals(RevocationType.OCSP)) {
            ocspVerify(this.certInfo.getCertificateX509(), issuer);
        }
    }

    public final void verifyExpiredDate() throws VerifyCertificateException {
        verifyDate(this.certInfo.getCertificateX509(), revocation.getDateToVerify());
    }

    private void verifyDate(X509Certificate cert, Calendar calendar) throws VerifyCertificateException {
        if (cert.hasUnsupportedCriticalExtension()) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("unsupported.critical.extension"));
        }
        try {
            cert.checkValidity(calendar.getTime());
        } catch (Exception e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.expired") + Utilities.formatDate(calendar.getTime()));
        }
    }

    private X509Certificate loadCA(String commonName) throws VerifyCertificateException {
        caKeystore = loadCacertsKeyStore(revocation.getPathKeystore(), revocation.getStreamKeyStore());
            

        try {
            Enumeration<String> localEnumeration = caKeystore.aliases();
            while (localEnumeration.hasMoreElements()) {
                String str = (String) localEnumeration.nextElement();
                if (caKeystore.isCertificateEntry(str)) {
                    Certificate localCertificate = caKeystore.getCertificate(str);
                    if (localCertificate instanceof X509Certificate) {
                        String[] array = ((X509Certificate) localCertificate).getSubjectDN().getName().split(",");
                        for (int j = 0; j < array.length; j++) {
                            if (array[j].trim().startsWith("CN=")) {

                                if (array[j].substring(3).trim().equals(commonName)) {

                                    return (X509Certificate) localCertificate;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("keystore.read") + e.getMessage());
        }

        //No coincide las CA locales con el certificado
        throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.certificate"));
    }

    private void ocspVerify(X509Certificate cert, X509Certificate issuer) throws VerifyCertificateException {
        OcspClient ocspClient;
        String server = this.revocation.getOcspServer();
        if (server == null || server.isEmpty()) {
            server = certInfo.getOcspURL();

        }
//        if (this.certParams.getRevocationVerify().isOcspProxy()) {
//            try {
//                ocspClient = new OcspClient(cert, issuer, server, this.certParams.getRevocationVerify().getProxyOscp(), this.certParams.getRevocationVerify().getProxyOscpPort(), this.certParams.getRevocationVerify().getProxyOscpUser(), this.certParams.getRevocationVerify().getProxyOscpPassword());
//
//                OcspResponse resp = ocspClient.ocspRequest();
//                if (resp.isRevoke()) {
//                    if (resp.getRevokeDate().compareTo(this.certParams.getRevocationVerify().getCalendar().getTime()) < 0) {
//                        throw new VerifyCertificateException(formatDate(resp.getRevokeDate()), 7);
//                    }
//                } else if (resp.isUnknow()) {
//                    throw new VerifyCertificateException(resp.getMessage(), 19);
//                }
//            } catch (OcspException e) {
//                throw new VerifyCertificateException(e.getMessage(), 19);
//            }
//        } else {
        ocspClient = new OcspClient(cert, issuer, server);
        OcspResponse resp = ocspClient.ocspRequest();
        if (resp.isRevoke()) {
            if (resp.getRevokeDate().compareTo(this.revocation.getDateToVerify().getTime()) < 0) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("certificate.annulled") + Utilities.formatDate(resp.getRevokeDate()));
            }
        } else if (resp.isUnknow()) {
            //esta entrando a es desconocido
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("ocsp.unknow.answer"));
        }

//        }
    }

    private KeyStore loadCacertsKeyStore(String keyStorePath, InputStream keyStoreStream) throws VerifyCertificateException {
        File file = null;
        InputStream fin = null;
        boolean propio = false;
        if (keyStoreStream != null) {
            fin = keyStoreStream;
            propio = true;
        } else if (keyStorePath == null || keyStorePath.equals("")) {
            file = new File(System.getProperty("java.home") + "/lib/security/cacerts");
        } else {
            file = new File(keyStorePath);
            propio = true;
        }
        if (fin == null) {
            try {
                fin = new FileInputStream(file);
            } catch (FileNotFoundException ex) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.valid"));

            }
        }

        KeyStore k;
        try {
            k = KeyStore.getInstance("JKS");
        } catch (KeyStoreException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.jks.found"));

        }
        String password;
        if (!propio) {
            password = "changeit";
        } else {
            password = "willman";
        }
        try {
            k.load(fin, password.toCharArray());
        } catch (NoSuchAlgorithmException e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.keystore.decode"));
        } catch (CertificateException e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.keystore.data"));
        } catch (IOException e) {
            if (e.getMessage().toString().contains("password was incorrect")) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.keystore.password"));
            } else {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.trust.keystore.right"));
            }
        } finally {
            try {
                if (fin != null) {
                    fin.close();
                }
            } catch (IOException ex) {
            }
        }




        return k;

    }
}
