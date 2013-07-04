/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import co.softluciona.certificate.CertificateInfo;
import co.softluciona.certificate.verify.revocation.RevocationProperties;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author user
 */
public class CertificateFromX509 extends CertificateVerify {

    private X509Certificate certificateX509 = null;
    private PrivateKey privateKey = null;
    private Certificate[] certificateChain = null;
    private Provider provider = null;
    
    public CertificateFromX509(X509Certificate certificateX509, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.certificateX509 = certificateX509;
        validate();
    }

    public CertificateFromX509(X509Certificate certificateX509, PrivateKey privateKey , Certificate[] certificateChain,
            Provider provider, RevocationProperties revocation) throws VerifyCertificateException {
        super(revocation);
        this.certificateX509 = certificateX509;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.provider = provider;
        validateAll();
        validate();
    }

    
    protected final void validateAll() throws VerifyCertificateException {
        if (this.privateKey == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.privateKey"));
        }
        if (this.certificateChain == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.certificateChain"));
        }
        if (this.provider == null) {
            this.provider = new BouncyCastleProvider();
        }
        
    }
    
    @Override
    protected final void validate() throws VerifyCertificateException {
        if (this.certificateX509 == null) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("no.certificateX509"));
        }
        this.certInfo = new CertificateInfo(certificateX509, privateKey, certificateChain, provider);
    }
    
    
}
