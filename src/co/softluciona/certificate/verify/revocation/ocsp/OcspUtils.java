package co.softluciona.certificate.verify.revocation.ocsp;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Clase que implementa los m�todos que sirven de utilidad en el proceso de
 * validar un certificado por medio de una petici�n OCSP
 *
 */
public class OcspUtils {

    /**
     * Umbral de tiempo para la �ltima actualizaci�n contra la lista de
     * revocaci�n de la VA
     */
    private final static long TIME_LIMIT = 10000;
    // Mensajes de error y de informaci�n
	/*
     private final static String ERROR_ID_CERT = "Error obteniendo el identificador " +
     "del certificado que se desea verificar.";
     private final static String ERROR_IO_SERVER = "Error leyendo o escribiendo " +
     "datos en la conexi�n con el servidor OCSP.";
     private final static String ERROR_MALFORMED_REQUEST = "Error: Petici�n inv�lida.";
     private final static String ERROR_INTERNAL = "Error: Problema interno " +
     "en el servidor OCSP.";
     private final static String ERROR_TRY_LATER = "Error: Intente de nuevo m�s tarde.";
     private final static String ERROR_SIG_REQUIRED = "Error: La petici�n debe estar " +
     "firmada.";
     private final static String ERROR_UNAUTHORIZED = "Error: Debe autenticarse " +
     "con el servidor OCSP.";
     private final static String ERROR_INVALID_CERT_SIGNATURE = "La firma del certificado a verificar " +
     "no es v�lida.";
     private final static String ERROR_INVALID_KEY = "La llave p�blica del emisor " +
     "no es v�lida.";
     private final static String ERROR_INVALID_ALG = "El algoritmo utilizado para la  " +
     "firma del certificado no es v�lido.";
     private final static String ERROR_DIFFERENT_ID = "El identificador del certificado que " +
     "se obtuvo en la respuesta no corresponde con el certificado que se desea " +
     "verificar.";
     private final static String ERROR_PROCESS_RESPONSE = "Se produjo un error en el " +
     "procesamiento de la respuesta OCSP.";
     private final static String ERROR_INVALID_PROVIDER = "Proveedor incorrecto.";
     private final static String ERROR_CERT_CREATION = "Error creando el objeto " +
     "certificado en el sistema.";
     private final static String ERROR_CERT_FILE = "Error al leer el archivo del certificado.";
     private final static String ERROR_URL_OCSP = "Error leyendo el archivo del certificado " +
     "para obtener la URL del servidor OCSP.";
     private final static String ERROR_READ_AIA = "Error obteniendo el Acceso a la " +
     "informaci�n de autoridad.";
     private final static String ERROR_CERT_EXPIRED = "Alguno de los certificados ha expirado.";
     private final static String ERROR_CERT_NOT_YET_VALID = "Alguno de los certificados " +
     "todav�a no es v�lido.";
     private final static String ERROR_READ_CERT = "Error al leer alg�n certificado.";
     */
    private final static String ERROR_INVALID_SIGNATURE = "La firma de la respuesta "
            + "no es v�lida.";
    private final static String VALID_SIGNATURE = "La firma de la respuesta "
            + "es v�lida.";
    private final static String CERT_STATUS_GOOD = "Estado del certificado: good.";
    private final static String CERT_STATUS_REVOKED = "Estado del certificado: revoked.";
    private final static String CERT_STATUS_UNKNOWN = "Estado del certificado: unknown.";
    private final static String TIME_LIMIT_EXCEEDED = "L�mite de tiempo de espera excedido: ";
    private final static String MILISECONDS = " milisegundos.";
    private final static String X509 = "X.509";
    private final static String EXTENDED_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
    public static final String OCSP_OID = "1.3.6.1.5.5.7.48.1";

    /**
     * Constructor vac�o
     */
    public OcspUtils() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * M�todo que genera una solicitud OCSP
     *
     * @param certToVerify Certificado del que se quiere verificar el estado
     * @param issuerCert	Certificado emisor del certificado a verificar
     * @return	OCSPReq Solicitud OCSP que se ha generado dados los par�metros
     * @throws OcspException	Se lanza esta excepci�n en caso de haber alg�n
     * inconveniente leyendo la informaci�n de los certificados
     */
    public OCSPReq generateOcspRequest(X509Certificate certToVerify,
            X509Certificate issuerCert) throws VerifyCertificateException {
        try {
            // Se obtiene el identificador del certificado que se quiere verificar
            CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerCert,
                    certToVerify.getSerialNumber());

            OCSPReqGenerator generator = new OCSPReqGenerator();
            // Se adiciona el identificador del certificado del que se quiere obtener el estado
            generator.addRequest(id);

            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
            Vector<X509Extension> values = new Vector<X509Extension>();

            oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));

            // Se a�ade a la solicitud la extenci�n nonce
            generator.setRequestExtensions(new X509Extensions(oids, values));

            // Se genera la solicitud OCSP a partir los valores adicionados
            return generator.generate();
        } catch (OCSPException e) {
            e.printStackTrace();
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.cert.id"));
        }
    }

    /**
     * M�todo que env�a una solicitud HTTP al servidor OCSP con la informaci�n
     * de la solicitud OCSP suministrada
     *
     * @param ocspRequest	Solicitud OCSP con la informaci�n del certificado del
     * que se quiere obtener el estado y de su certificado emisor
     * @param ocspServer	Servidor OCSP al que se env�a la solicitud HTTP
     * @return	OCSPResp Respuesta OCSP obtenida
     * @throws OcspException Se lanza esta excepci�n si ocurre alg�n
     * inconveniente leyendo o escribiendo los datos de la solicitud OCSP
     */
    public OCSPResp generateHttpRequest(OCSPReq ocspRequest, String ocspServer)
            throws VerifyCertificateException {
        try {
            OCSPResp ret = null;

            // Se construye la solicitud HTTP
            URL iurl = new URL(ocspServer);
            HttpURLConnection urlConn = (HttpURLConnection) iurl.openConnection();
            urlConn.setRequestMethod("POST");
            urlConn.setDoOutput(true);
            urlConn.setRequestProperty("Content-type", "application/ocsp-request");
            urlConn.setRequestProperty("Accept", "application/ocsp-response");

            // Se env�a la solicitud
            DataOutputStream outStream = new DataOutputStream(urlConn.getOutputStream());
            outStream.write(ocspRequest.getEncoded());
            outStream.flush();
            outStream.close();

            // Se obtiene la respuesta del servidor OCSP
            InputStream inStream = (InputStream) urlConn.getContent();
            ret = new OCSPResp(inStream);
            inStream.close();

            return ret;
        } catch (IOException e) {
            //throw new OcspException(ERROR_IO_SERVER, e);
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.io.server"));
        }
    }

    /**
     * M�todo que env�a una solicitud HTTP al servidor OCSP con la informaci�n
     * de la solicitud OCSP mediante un proxy
     *
     * @param ocspRequest	Solicitud OCSP con la informaci�n del certificado del
     * que se quiere obtener el estado y de su certificado emisor
     * @param ocspServer	Servidor OCSP al que se env�a la solicitud HTTP
     * @param proxyServer Url del proxy por el que se realiza la conexi�n
     * @param proxyAuthentication Indica si la conexi�n con el proxy necesita
     * autenticaci�n
     * @param proxyUser Usuario de la conexi�n con el proxy
     * @param proxyPassword Contrase�a de la conexi�n con el proxy
     * @return	OCSPResp Respuesta OCSP obtenida
     * @throws OcspException Se lanza esta excepci�n si ocurre alg�n
     * inconveniente leyendo o escribiendo los datos de la solicitud OCSP
     */
    public OCSPResp generateHttpRequest(OCSPReq ocspRequest, String ocspServer, String proxyServer,
            String proxyPort, boolean proxyAuthentication, String proxyUser, String proxyPassword)
            throws VerifyCertificateException {
        try {
            OCSPResp ret = null;

            if (proxyAuthentication == true) {
                Authenticator.setDefault(new ProxyAuthenticator(proxyUser, proxyPassword));
            }

            InetSocketAddress isa = new InetSocketAddress(proxyServer,
                    (new Integer(proxyPort)).intValue());
            Proxy proxy = new Proxy(Proxy.Type.HTTP, isa);

            // Se construye la solicitud HTTP
            URL iurl = new URL(ocspServer);
            HttpURLConnection urlConn = (HttpURLConnection) iurl.openConnection(proxy);
            urlConn.setRequestMethod("POST");
            urlConn.setDoOutput(true);
            urlConn.setRequestProperty("Content-type", "application/ocsp-request");
            urlConn.setRequestProperty("Accept", "application/ocsp-response");

            // Se env�a la solicitud
            DataOutputStream outStream = new DataOutputStream(urlConn.getOutputStream());
            outStream.write(ocspRequest.getEncoded());
            outStream.flush();
            outStream.close();

            // Se obtiene la respuesta del servidor OCSP
            InputStream inStream = (InputStream) urlConn.getContent();
            ret = new OCSPResp(inStream);
            inStream.close();

            return ret;
        } catch (IOException e) {
            throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.io.server"));
            //throw new OcspException(ERROR_IO_SERVER, e);
        }
    }

    /**
     * M�todo que procesa la respuesta OCSP para extraer la informaci�n de
     * verificaci�n de un certificado
     *
     * @param response	Respuesta OCSP obtenida
     * @param certToVerify	Certificado del que se quiere verificar el estado
     * @param issuerCert	Certificado emisor del certificado a verificar
     * @return String	Mensaje que resulta del procesamiento de la solicitud OCSP
     * @throws OcspException Se lanza una excepci�n de este tipo al obtener
     * alg�n error en el proceso
     */
    public OcspResponse processOcspResponse(OCSPResp response, X509Certificate certToVerify,
            X509Certificate issuerCert) throws VerifyCertificateException {
        OcspResponse oscpResponse = new OcspResponse();
        String ret = null;

        // Se lee el el estado de la respuesta
        switch (response.getStatus()) {
            case OCSPResponseStatus.MALFORMED_REQUEST:
                //throw new OcspException(ERROR_MALFORMED_REQUEST);
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.bad.request"));

            case OCSPResponseStatus.INTERNAL_ERROR:
                //throw new OcspException(ERROR_INTERNAL);
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.internal.error"));

            case OCSPResponseStatus.TRY_LATER:
                //throw new OcspException(ERROR_TRY_LATER);
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.try.later"));

            case OCSPResponseStatus.SIG_REQUIRED:
                //throw new OcspException(ERROR_SIG_REQUIRED);
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.sig.required"));

            case OCSPResponseStatus.UNAUTHORIZED:
                //throw new OcspException(ERROR_UNAUTHORIZED);
                throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.unauthorized"));

            case OCSPResponseStatus.SUCCESSFUL:
                try {
                    // En caso de ser exitosa la respuesta, se verifica su firma
                    // Existen tres casos para la firma de la respuesta
                    // Este es el primer caso: La respuesta OCSP viene firmada por el
                    // certificado emisor del certificado que se quiere verificar y 
                    // que fue enviado en la solicitud OCSP

                    BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
                    boolean verified = basicResp.verify(issuerCert.getPublicKey(),
                            BouncyCastleProvider.PROVIDER_NAME);

                    if (verified) {
                        ret = (ret == null)
                                ? ret = VALID_SIGNATURE : ret.concat(VALID_SIGNATURE);
                    } else {
                        // Este es el segundo caso: La respuesta OCSP viene firmada
                        // por un certificado emitido por el mismo certificado emisor
                        // del certificado que se desea verificar. Adicionalmente se
                        // valida que el certificado que firma la respuesta tenga presente
                        // la llave de extensi�n de uso para firmar respuestas OCSP

                        X509Certificate[] certs =
                                basicResp.getCerts(BouncyCastleProvider.PROVIDER_NAME);

                        for (X509Certificate tempCert : certs) {
                            List<String> tempList = tempCert.getExtendedKeyUsage();
                            if (tempList != null) {
                                //verifyCertificates(tempCert, issuerCert);
                                verified = tempList.contains(EXTENDED_OCSP_SIGNING);
                            }
                        }


                        if (verified) {
                            ret = (ret == null) ? ret = VALID_SIGNATURE : ret.concat(VALID_SIGNATURE);
                        } else {
                            ret = (ret == null) ? ret = ERROR_INVALID_SIGNATURE : ret.concat(ERROR_INVALID_SIGNATURE);
                        }
                    }

                    // Se lee el conjunto de respuestas que est�n dentro de la respuesta global
                    SingleResp[] singleResps = basicResp.getResponses();
                    for (SingleResp singleResp : singleResps) {
                        CertificateID responseCertificateId = singleResp.getCertID();

                        CertificateID id = new CertificateID(CertificateID.HASH_SHA1,
                                issuerCert, certToVerify.getSerialNumber());

                        // Se verifica que el identificador del certificado del que se desea 
                        // obtener el estado es el mismo que est� en la respuesta suministrada
                        if (id.equals(responseCertificateId)) {
                            Date thisUpdate = singleResp.getThisUpdate();
                            Date validationDate = new Date();
                            long dt = Math.abs(
                                    thisUpdate.getTime() - validationDate.getTime());
                            // Se verifica si se ha excedido el tiempo del umbral establecido
                            // de la �ltima actualizaci�n sobre la CRL
                            if (dt > TIME_LIMIT) {
                                ret = (ret == null)
                                        ? ret = TIME_LIMIT_EXCEEDED + dt + MILISECONDS
                                        : ret.concat(TIME_LIMIT_EXCEEDED + dt + MILISECONDS);
                            }

                            if (singleResp.getCertStatus() == null) {
                                // El estado del certificado es: good
                                ret = (ret == null)
                                        ? ret = CERT_STATUS_GOOD : ret.concat(CERT_STATUS_GOOD);
                                oscpResponse.setGood(true);
                            } else {
                                if (singleResp.getCertStatus() instanceof RevokedStatus) {
                                    // El estado del certificado es: revoked
                                    ret = (ret == null) ? ret = CERT_STATUS_REVOKED : ret.concat(CERT_STATUS_REVOKED);
                                    oscpResponse.setRevokeDate(((RevokedStatus) singleResp.getCertStatus()).getRevocationTime());
                                    oscpResponse.setRevoke(true);

                                } else if (singleResp.getCertStatus() instanceof UnknownStatus) {
                                    // El estado del certificado es: unknown
                                    ret = (ret == null) ? ret = CERT_STATUS_UNKNOWN : ret.concat(CERT_STATUS_UNKNOWN);
                                    oscpResponse.setUnknow(true);
                                }
                            }
                        } else {
                             throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.wrong.id"));
                            //throw new OcspException(ERROR_DIFFERENT_ID);
                        }
                    }
                } catch (OCSPException ex) {
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.cert.id"), ex);
                } catch (NoSuchProviderException ex1) {
                    //throw new OcspException(ERROR_INVALID_PROVIDER, ex1);
                     throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.provider"), ex1);
                } catch (CertificateParsingException ex2) {
                    //throw new OcspException(ERROR_CERT_FILE, ex2);
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.cert.error"), ex2);
                }
                break;

        }
        oscpResponse.setMessage(ret);
        return oscpResponse;
    }

  

   

    /**
     * Recorre el certificado �nicamente para saber el estado del certificado
     *
     * @param response	Respuesta de la que se quiere extraer el estado del
     * certificado
     * @return	String El retorno se limita a informar si el estado del
     * certificado al que corresponde la respuesta suministrada es "good",
     * "revoked" o "unknown"
     * @throws OCSPException
     */
    public String getCertificateStatus(OCSPResp response) throws OCSPException {
        String ret = null;

        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();

        // Se lee el conjunto de respuestas que est�n dentro de la respuesta global
        SingleResp[] singleResps = basicResp.getResponses();
        for (SingleResp singleResp : singleResps) {
            if (singleResp.getCertStatus() == null) {
                // El estado del certificado es: good
                ret = (ret == null)
                        ? ret = CERT_STATUS_GOOD : ret.concat(CERT_STATUS_GOOD);
            } else {
                if (singleResp.getCertStatus() instanceof RevokedStatus) {
                    // El estado del certificado es: revoked
                    ret = (ret == null)
                            ? ret = CERT_STATUS_REVOKED : ret.concat(CERT_STATUS_REVOKED);
                } else if (singleResp.getCertStatus() instanceof UnknownStatus) {
                    // El estado del certificado es: unknown
                    ret = (ret == null)
                            ? ret = CERT_STATUS_UNKNOWN : ret.concat(CERT_STATUS_UNKNOWN);
                }
            }
        }
        return ret;
    }

    /**
     * Escribe un arreglo de bytes al archivo especificado en la ruta
     *
     * @param encoded	Arreglo de bytes a escribir
     * @param path	Ubicaci�n del archivo que se quiere escribir
     * @throws IOException	Se lanza una excepci�n de este tipo si se generan
     * problemas al escribir el archivo
     */
    public void writeBytesToFile(byte[] encoded, String path) throws IOException {
        FileOutputStream outStream = new FileOutputStream(path);
        outStream.write(encoded);
        outStream.flush();
        outStream.close();
    }

    /**
     * Lee un archivo y pone la informaci�n en un arreglo de bytes
     *
     * @param path	Ubicaci�n del archivo que se desea leer
     * @return	Arreglo de bytes con la informaci�n le�da del archivo
     * @throws IOException	Se lanza una excepci�n de este tipo si se generan
     * problemas al leer el archivo
     */
    public byte[] readBytesToFile(String path) throws IOException {
        byte[] ret = null;
        FileInputStream inStream = new FileInputStream(path);
        inStream.read(ret);
        inStream.close();
        return ret;
    }
}