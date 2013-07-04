/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Extensions;

/**
 *
 * @author user
 */
public class CertificateInfo {

    private X509Certificate certificateX509;
    private Certificate[] certificateChain;
    private PrivateKey privateKey;
    private Provider provider;
    private HashMap<String, String> info;
    private HashMap<String, String> infoIssuer;
    private String ocspURL;
    private String crlURL;
    private static final String crl_oid = "2.5.29.31";
    public static final String crl_protocol = "http://";

    public CertificateInfo(X509Certificate certificateX509, PrivateKey privateKey, Certificate[] certificateChain, Provider provider) {
        this.certificateX509 = certificateX509;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.provider = provider;
        info = getOIDsAndValues(this.certificateX509.getSubjectDN().getName());
        infoIssuer = getOIDsAndValues(this.certificateX509.getIssuerDN().getName());
        this.ocspURL = loadOcspUrl(certificateX509);
        this.crlURL = loadCrlUrl(certificateX509);

    }

    private HashMap<String, String> getOIDsAndValues(String distinguishedName) {
        HashMap<String, String> info_ = new HashMap<String, String>();
        String[] stringArray = distinguishedName.split(",");
        String[] stringArrayTemp;

        for (int i = 0; i < stringArray.length; i++) {
            stringArrayTemp = stringArray[i].split("=");
            if (stringArrayTemp.length == 2) {
                info_.put(stringArrayTemp[0].toString(), stringArrayTemp[1].toString().trim());
            }
        }
        return info_;
    }

    private String loadCrlUrl(X509Certificate certificate) {
        
        String crlDistributionPoints = new String(
                certificate.getExtensionValue(crl_oid));
        String[] crlDistributionPointsTokens = crlDistributionPoints
                .split(crl_protocol);
        boolean isdownload = false;
        for (int j = 0; j < crlDistributionPointsTokens.length; j++) {
            int indexCRL = crlDistributionPointsTokens[j]
                    .lastIndexOf(".crl");
            if (indexCRL != -1 && !isdownload) {
                return crl_protocol
                        + crlDistributionPointsTokens[j].substring(0,
                        indexCRL) + ".crl";
            }
        }
       
        return null;
    }

   
    private String loadOcspUrl(X509Certificate certificate) {
        ASN1Primitive obj;
        try {
            obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.getId());
        } catch (IOException e) {
          return null;
        }
        if (obj == null) {
            return null;
        }

        ASN1Sequence AccessDescriptions = (ASN1Sequence) obj;
        for (int i = 0; i < AccessDescriptions.size(); i++) {
            ASN1Sequence AccessDescription =
                    (ASN1Sequence) AccessDescriptions.getObjectAt(i);
            if (AccessDescription.size() != 2) {
               return null;
            } else {

                String AccessLocation = getStringFromGeneralName(
                        (ASN1Primitive) AccessDescription.getObjectAt(1));
                if (AccessLocation == null) {
                    return null;
                } else {
                    return AccessLocation;
                }
            }
        }

        return null;
    }

    private String getStringFromGeneralName(ASN1Primitive names) {
        DERTaggedObject taggedObject = (DERTaggedObject) names;
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
    }

    private ASN1Primitive getExtensionValue(X509Certificate cert, String oid)
            throws IOException {
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }

    /**
     * @return the certificateX509
     */
    public X509Certificate getCertificateX509() {
        return certificateX509;
    }

    /**
     * @return the info
     */
    public HashMap<String, String> getInfo() {
        return info;
    }

    /**
     * @return the infoIssuer
     */
    public HashMap<String, String> getInfoIssuer() {
        return infoIssuer;
    }

    /**
     * @return the certificateChain
     */
    public Certificate[] getCertificateChain() {
        return certificateChain;
    }

    /**
     * @return the privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @return the provider
     */
    public Provider getProvider() {
        return provider;
    }

    /**
     * @return the ocspURL
     */
    public String getOcspURL() {
        return ocspURL;
    }

    /**
     * @return the crlURL
     */
    public String getCrlURL() {
        return crlURL;
    }
}
