/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.certificate.CertificateInfo;
import co.softluciona.certificate.verify.revocation.RevocationProperties;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 *
 * @author user
 */
public class CertificateFromKeyStore extends CertificateVerify {

    private KeyStore certificateKeyStores;
    private String passwordCertificate;
    private String alias;

    public CertificateFromKeyStore(KeyStore certificateKeyStores, String passwordCertificate, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.alias = "";
        this.certificateKeyStores = certificateKeyStores;
        this.passwordCertificate = passwordCertificate;
        validate();
    }

    public CertificateFromKeyStore(KeyStore certificateKeyStores, String passwordCertificate, String alias, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.alias = alias;
        this.certificateKeyStores = certificateKeyStores;
        this.passwordCertificate = passwordCertificate;
        validate();
    }

    @Override
    protected final void validate() throws VerifyCertificateException {
        if (this.certificateKeyStores == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.certificateBytes"));
        }
        if (this.passwordCertificate == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.passwordCertificate"));
        }
//        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = certificateKeyStores;
        if (this.alias.isEmpty()) {
            try {
                this.alias = (String) ks.aliases().nextElement();
            } catch (KeyStoreException ex) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.alias"));
            }
        }
        X509Certificate certificateX509;
        try {
            certificateX509 = (X509Certificate) ks.getCertificate(alias);
        } catch (KeyStoreException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.x509"));
        }
        Certificate[] certificateChain;
        try {
            certificateChain = ks.getCertificateChain(alias);
        } catch (KeyStoreException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.chain"));
        }
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) ks.getKey(alias, this.passwordCertificate.toCharArray());
        } catch (KeyStoreException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.key"));
        } catch (NoSuchAlgorithmException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.key"));
        } catch (UnrecoverableKeyException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.key"));
        }
        Provider provider = ks.getProvider();
        this.certInfo = new CertificateInfo(certificateX509, privateKey, certificateChain, provider);
    }
}
