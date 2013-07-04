/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.certificate.CertificateInfo;
import co.softluciona.certificate.verify.revocation.RevocationProperties;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 *
 * @author user
 */
public class CertificateFromBytes extends CertificateVerify {

    private byte[] certificateBytes;
    private String passwordCertificate;
    private String alias;

    public CertificateFromBytes(byte[] certificateBytes, String passwordCertificate, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.alias = "";
        this.certificateBytes = certificateBytes;
        this.passwordCertificate = passwordCertificate;
        validate();
    }

    public CertificateFromBytes(byte[] certificateBytes, String passwordCertificate, String alias, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.alias = alias;
        this.certificateBytes = certificateBytes;
        this.passwordCertificate = passwordCertificate;
        validate();
    }

    @Override
    protected final void validate() throws VerifyCertificateException {
        if (this.certificateBytes == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.certificateBytes"));
        }
        if (this.passwordCertificate == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.passwordCertificate"));
        }
//        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = getKeyStoreFromBytes();
        
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
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.key"));
        }
        Provider provider = ks.getProvider();
        this.certInfo = new CertificateInfo(certificateX509, privateKey, certificateChain, provider);
    }
    
    private KeyStore getKeyStoreFromBytes() throws VerifyCertificateException{
         KeyStore ks;
        try {
            ks = KeyStore.getInstance("pkcs12");
        } catch (KeyStoreException ex) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.pkcs12.found"));
        }

        ByteArrayInputStream certificate = new ByteArrayInputStream(certificateBytes);
        try {
            ks.load(certificate, passwordCertificate.toCharArray());
        } catch (NoSuchAlgorithmException e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.decode"));
        } catch (CertificateException e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.data"));
        } catch (IOException e) {
            if (e.getMessage().toString().startsWith("failed to decryp")) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.password"));
            } else {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.right"));
            }
        }
        if (this.alias.isEmpty()) {
            try {
                this.alias = (String) ks.aliases().nextElement();
            } catch (KeyStoreException ex) {
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.keystore.alias"));
            }
        }
        return ks;
    }
}
