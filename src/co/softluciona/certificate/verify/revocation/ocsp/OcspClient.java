package co.softluciona.certificate.verify.revocation.ocsp;

import co.softluciona.certificate.verify.exception.VerifyCertificateException;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;


/**
 * Clase que implementa los m�todos que se utilizan para generar
 * peticiones OCSP
 *
 */
public class OcspClient 
{
	//********************************************
	// Mensajes de error y de informaci�n
	//********************************************
	
//	private final static String ERROR_READ_CERT = "Error al leer alg�n certificado.\r\n";
//	private final static String ERROR_READ_RESPONSE = "Error al leer la informaci�n de la " +
//			"respuesta OCSP suministrada.\r\n";
//	private final static String ERROR_READ_REQUEST = "Error al leer la informaci�n de la " +
//			"solicitud OCSP suministrada.\r\n";
//	private final static String ERROR_WRITE_RESPONSE = "Error al escribir la respuesta OCSP " +
//			"en la ruta suministrada.\r\n";
//	private final static String ERROR_WRITE_REQUEST = "Error al escribir la solicitud OCSP " +
//			"en la ruta suministrada.\r\n";
//	private final static String ERROR_OCSP_URL = "La URL del servidor OCSP no es v�lida.\r\n";
//	private final static String ERROR_INVALID_PROVIDER = "Proveedor incorrecto.\r\n";
	

	
	
	//********************************************
	// Atributos
	//********************************************
	
	/**
	 * Instancia de la clase OcspUtils
	 */
	private OcspUtils ocspUtils;
	
	/**
	 * Certificado a verificar
	 */
	private X509Certificate certToVerify;
	
	/**
	 * Certificado emisor
	 */
	private X509Certificate issuerCert;
	
	/**
	 * Url del servidor OCSP
	 */
	private String ocspServer;
	
	/**
	 * Solicitud al servidor OCSP
	 */
	private OCSPReq request;
	
	/**
	 * Respuesta del servidor OCSP
	 */
	private OCSPResp response;
	
	/**
	 * Booleano que indica si se utiliza o no un proxy para la conexi�n
	 */
	private boolean useProxy;
	
	/**
	 * Booleano que indica si el proxy necesita autenticaci�n
	 */
	private boolean proxyAuthentication;
	
	/**
	 * Direcci�n del proxy
	 */
	private String proxy;
	
	/**
	 * Puerto para la conexi�n con el proxy
	 */
	private String proxyPort;
	
	/**
	 * Nombre de usuario para la autenticaci�n en el proxy
	 */
	private String proxyUser;
	
	/**
	 * Contrase�a para la autenticaci�n en el proxy
	 */
	private String proxyPassword;
	
	
	
	
	//********************************************
	// Constructores
	//********************************************
	
	/**
	 * M�todo Constructor vac�o <br />
	 * Se inicializan todos los atributos en null
	 */
	public OcspClient()
	{
		ocspUtils = new OcspUtils();
		certToVerify = null;
		issuerCert =  null;
		ocspServer = "";
		request = null;
		response = null;
		useProxy = false;
		proxyAuthentication = false;
		proxy = null;
		proxyUser = null;
		proxyPassword = null;
	}
	
	
	
	/**
	 * M�todo Constructor con los objetos X509Certificate de los certificados
	 * @param certToVerify Objeto X509Certificate del certificado que se quiere verificar
	 * @param issuerCert Objeto X509Certificate del certificado emisor del que se quiere
	 * 		verificar
	 * @throws OcspException Se lanza esta excepci�n si ocurre alg�n error
	 * 		inicializando los atributos de la clase
	 */
	public OcspClient(X509Certificate certToVerify, X509Certificate issuerCert) throws VerifyCertificateException
	{
		ocspUtils = new OcspUtils();
		ocspServer = null;
		request = null;
		response = null;
		useProxy = false;
		proxyAuthentication = false;
		proxy = null;
		proxyUser = null;
		proxyPassword = null;
		
		if(certToVerify != null && issuerCert != null)
		{
			this.certToVerify = certToVerify;
			this.issuerCert = issuerCert;

			// Se verifica la validez de los certificados
			//ocspUtils.verifyCertificates(this.certToVerify, this.issuerCert);
		}
		
	}
	
		
	/**
	 * M�todo Constructor con los objetos X509Certificate de los certificados y el servidor OCSP
	 * @param certToVerify Objeto X509Certificate del certificado que se quiere verificar
	 * @param issuerCert Objeto X509Certificate del certificado emisor del que se quiere
	 * 		verificar
	 * @param ocspServer Url del Servidor OCSP
	 * @throws OcspException Se lanza esta excepci�n si ocurre alg�n error
	 * 		inicializando los atributos de la clase
	 */
	public OcspClient(X509Certificate certToVerify, X509Certificate issuerCert, String ocspServer) 
			throws VerifyCertificateException
	{
		ocspUtils = new OcspUtils();
		this.ocspServer = ocspServer;
		request = null;
		response = null;
		useProxy = false;
		proxyAuthentication = false;
		proxy = null;
		proxyUser = null;
		proxyPassword = null;
		if(certToVerify != null && issuerCert != null)
		{
			this.certToVerify = certToVerify;
			this.issuerCert = issuerCert;
			// Se verifica la validez de los certificados
			//ocspUtils.verifyCertificates(this.certToVerify, this.issuerCert);
		}		
	}
	
	/**
	 * M�todo Constructor con los objetos X509Certificate de los certificados, el servidor
	 * OCSP y los datos de la conexi�n por proxy
	 * @param certToVerify Objeto X509Certificate del certificado que se quiere verificar
	 * @param issuerCert Objeto X509Certificate del certificado emisor del que se quiere
	 * 		verificar
	 * @param ocspServer Url del Servidor OCSP
	 * @param proxy Url del proxy
	 * @param proxyUser Usuario para la autenticaci�n con el proxy
	 * @param proxyPassword Contrase�a para la autenticaci�n con el proxy
	 * @throws OcspException Se lanza esta excepci�n si ocurre alg�n error
	 * 		inicializando los atributos de la clase
	 */
	public OcspClient(X509Certificate certToVerify, X509Certificate issuerCert, String ocspServer,
			String proxy, String proxyPort, String proxyUser, String proxyPassword) 
			throws VerifyCertificateException
	{
		ocspUtils = new OcspUtils();
		this.ocspServer = ocspServer;
		request = null;
		response = null;
		
		if(certToVerify != null && issuerCert != null)
		{
			this.certToVerify = certToVerify;
			this.issuerCert = issuerCert;
			
			// Se verifica la validez de los certificados
			//ocspUtils.verifyCertificates(this.certToVerify, this.issuerCert);
		}
		
		
		useProxy = true;
		this.proxy = proxy;
		this.proxyPort = proxyPort;
		
		if(proxyUser == null && proxyPassword == null)
		{
			proxyAuthentication = false;
		}
		else
		{
			proxyAuthentication = true;
			this.proxyUser = proxyUser;
			this.proxyPassword = proxyPassword;
		}
	}
	
	
	
	/**
	 * M�todo Constructor con los objetos X509Certificate de los certificados y los 
	 * datos de la conexi�n por proxy
	 * @param certToVerify Objeto X509Certificate del certificado que se quiere verificar
	 * @param issuerCert Objeto X509Certificate del certificado emisor del que se quiere
	 * 		verificar
	 * @param proxy Url del proxy
	 * @param proxyUser Usuario para la autenticaci�n con el proxy
	 * @param proxyPassword Contrase�a para la autenticaci�n con el proxy
	 * @throws OcspException Se lanza esta excepci�n si ocurre alg�n error
	 * 		inicializando los atributos de la clase
	 */
	public OcspClient(X509Certificate certToVerify, X509Certificate issuerCert, 
			String proxy, String proxyPort, String proxyUser, String proxyPassword) 
			throws VerifyCertificateException
	{
		ocspUtils = new OcspUtils();
		this.ocspServer = null;
		request = null;
		response = null;
		
		if(certToVerify != null && issuerCert != null)
		{
			this.certToVerify = certToVerify;
			this.issuerCert = issuerCert;
			
			// Se verifica la validez de los certificados
			//ocspUtils.verifyCertificates(this.certToVerify, this.issuerCert);
		}
				
		useProxy = true;
		this.proxy = proxy;
		this.proxyPort = proxyPort;
		
		if(proxyUser == null && proxyPassword == null)
		{
			proxyAuthentication = false;
		}
		else
		{
			proxyAuthentication = true;
			this.proxyUser = proxyUser;
			this.proxyPassword = proxyPassword;
		}
	}
	
	
	
	//********************************************
	// M�todos
	//********************************************
	
	/**
	 * M�todo que genera una petici�n OCSP
	 * @return String Cadena de caracteres indicando las operaciones realizadas
	 * @throws OcspException Se genera una excepci�n de este tipo cuando se produzca 
	 * 			cualquier excepci�n en el proceso
	 */
	public OcspResponse ocspRequest() throws VerifyCertificateException
	{
		// Se obtiene la petici�n OCSP
		request = ocspUtils.generateOcspRequest(certToVerify, issuerCert);
		
		if(ocspServer == null)
		{
                    throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.url.error"));
			// Se obtiene la URL del servidor OCSP al que se le enviar� la petici�n
		}
		
		// Se env�a la petici�n y se obtiene la respectiva respuesta
		if(useProxy)
		{
			response = ocspUtils.generateHttpRequest(request, ocspServer, 
					proxy, proxyPort, proxyAuthentication, proxyUser, proxyPassword);
		}
		else
		{
			response = ocspUtils.generateHttpRequest(request, ocspServer);
		}
		
		// Se procesa la respuesta para extraer la informaci�n que contiene
		return  ocspUtils.processOcspResponse(response, certToVerify, issuerCert);
	}
	
	/**
	 * M�todo que verifica la respuesta OCSP actual
	 * @return String	Mensaje obtenido de la verificaci�n de la respuesta OCSP actual 
	 * @throws OcspException	Se lanza una excepci�n de este tipo si ocurre alg�n error
	 * 				durante la verificaci�n de la respuesta OCSP
	 */
	public OcspResponse verifyOcspResponse() throws VerifyCertificateException
	{
		// Se procesa la respuesta que se encuentra almacenada en el atributo de
		// la clase y se devuelve el mensaje obtenido
		return ocspUtils.processOcspResponse(response, certToVerify, issuerCert);
	}
	
	/**
	 * Se informa sobre el estado del certificado que se encuentra en 
	 * la respuesta actual
	 * @return	String estado del certificado obtenido de la respuesta actual
	 * @throws OcspException	Se lanza una excepci�n de este tipo en
	 * 			caso de haber alg�n error en la lectura de la respuesta actual
	 */
	public String getCertificateStatus() throws VerifyCertificateException
	{
		try 
		{
			return ocspUtils.getCertificateStatus(response);
		} 
		catch (OCSPException e) 
		{
			//throw new OcspException(ERROR_READ_RESPONSE, e);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"));
		}
	}
	
	/**
	 * Se escribe la solicitud OCSP actual a un archivo
	 * @param path	Ruta del archivo que se va a escribir
	 * @throws OcspException	Se lanza una excepci�n de este tipo en caso de
	 * 			haber alg�n problema con la escritura del archivo
	 */
	public void writeOcspRequestToFile(String path) throws VerifyCertificateException
	{
		try 
		{
			ocspUtils.writeBytesToFile(request.getEncoded(), path);
		} 
		catch (IOException e) 
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.write.error"));
			//throw new OcspException(ERROR_WRITE_REQUEST, e);
		}
	}
	
	/**
	 * Se escribe la respuesta OCSP actual a un archivo
	 * @param path	Ruta del archivo que se va a escribir
	 * @throws OcspException	Se lanza una excepci�n de este tipo en caso de
	 * 			haber alg�n problema con la escritura del archivo
	 */
	public void writeOcspResponseToFile(String path) throws VerifyCertificateException
	{
		try 
		{
			ocspUtils.writeBytesToFile(response.getEncoded(), path);
		} 
		catch (IOException e) 
		{
			//throw new OcspException(ERROR_WRITE_RESPONSE, e);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.write.error"));
		}
	}
	
	/**
	 * Se lee una solicitud OCSP de un archivo
	 * @param path	Ruta del archivo que se va a leer
	 * @throws OcspException	Se lanza una excepci�n de este tipo en caso de
	 * 			haber alg�n problema con la lectura del archivo
	 */
	public void readOcspRequestFromFile(String path) throws VerifyCertificateException
	{
		try 
		{
			byte[] requestBytes = ocspUtils.readBytesToFile(path);
			request = new OCSPReq(requestBytes);
		} 
		catch (IOException e) 
		{
			//throw new OcspException(ERROR_READ_REQUEST, e);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.read.error"));
		}
	}
	
	/**
	 * Se lee una solicitud OCSP de un archivo
	 * @param path	Ruta del archivo que se va a leer
	 * @throws OcspException	Se lanza una excepci�n de este tipo en caso de
	 * 			haber alg�n problema con la lectura del archivo
	 */
	public void readOcspResponseFromFile(String path) throws VerifyCertificateException
	{
		try 
		{
			byte[] responseBytes = ocspUtils.readBytesToFile(path);
			response = new OCSPResp(responseBytes);
		} 
		catch (IOException e) 
		{
			//throw new OcspException(ERROR_READ_RESPONSE, e);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.read.error"));
		}
	}
	
	/**
	 * M�todo que retorna los certificados que hay dentro de la solicitud OCSP actual
	 * @return	Arreglo de X509Certificate con los certificados de la solicitud OCSP
	 * @throws OcspException	Se lanza una excepci�n de este tipo si se produce alg�n
	 * 			tipo de error en el m�todo
	 */
	public X509Certificate[] getRequestCerts() throws VerifyCertificateException
	{
		try 
		{
			return request.getCerts(BouncyCastleProvider.PROVIDER_NAME);
		} 
		catch (NoSuchProviderException ex1) 
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.provide"));
			//throw new OcspException(ERROR_INVALID_PROVIDER, ex1);
		} 
		catch (OCSPException ex2) 
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"));
			//throw new OcspException(ERROR_READ_REQUEST, ex2);
		}
	}
	
	/**
	 * M�todo que retorna los certificados que hay dentro de la respuesta OCSP actual
	 * @return	Arreglo de X509Certificate con los certificados de la respuesta OCSP
	 * @throws OcspException	Se lanza una excepci�n de este tipo si se produce alg�n
	 * 			tipo de error en el m�todo
	 */
	public X509Certificate[] getResponseCerts() throws VerifyCertificateException
	{
		try 
		{
			BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
			return basicResp.getCerts(BouncyCastleProvider.PROVIDER_NAME);
		} 
		catch (OCSPException ex1) 
		{
			//throw new OcspException(ERROR_READ_RESPONSE, ex1);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"),ex1);
		}	
		catch (NoSuchProviderException ex2) 
		{
			//throw new OcspException(ERROR_INVALID_PROVIDER, ex2);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.provide"));
		} 
	}
	
	/**
	 * M�todo que retorna la firma de la solicitud OCSP actual
	 * @return	Arreglo de bytes con la firma de la solicitud OCSP
	 */
	public byte[] getRequestSignature()
	{
		return request.getSignature();
	}
	
	/**
	 * M�todo que retorna la firma de la respuesta OCSP actual
	 * @return	Arreglo de bytes con la firma de la respuesta OCSP
	 * @throws OcspException	Se lanza una excepci�n de este tipo 
	 * 			si existe alg�n problema leyendo la respuesta OCSP
	 */
	public byte[] getResponseSignature() throws VerifyCertificateException
	{
		try
		{
			BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
			return basicResp.getSignature();
		} 
		catch (OCSPException ex1) 
		{
			//throw new OcspException(ERROR_READ_RESPONSE, ex1);
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"),ex1);
		}
	}
	
	/**
	 * M�todo que retorna el OID del algoritmo utilizado para firmar la 
	 * respuesta OCSP
	 * @return	Cadena de caracteres con el OID correspondiente
	 * @throws OcspException	Se lanza una excepci�n de este tipo si se 
	 * 			presenta alg�n error al leer la respuesta OCSP
	 */
	public String getResponseSignAlgOID() throws VerifyCertificateException
	{
		try
		{
			BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
			return basicResp.getSignatureAlgOID();
		} 
		catch (OCSPException ex1) 
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"),ex1);
			//throw new OcspException(ERROR_READ_RESPONSE, ex1);
		}
	}
	
	/**
	 * M�todo que retorna el nombre del algoritmo utilizado para firmar
	 * la respuesta OCSP
	 * @return	Cadena de caracteres con el nombre del algoritmo
	 * @throws OcspException	Se lanza una excepci�n de este tipo si se
	 * 			presenta alg�n error al leer la respuesta OCSP
	 */
	public String getResponseSignAlgName() throws VerifyCertificateException
	{
		try
		{
			BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
			return basicResp.getSignatureAlgName();
		} 
		catch (OCSPException ex1) 
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.reponse.error"),ex1);
			//throw new OcspException(ERROR_READ_RESPONSE, ex1);
		}
	}
	
		
	
	//********************************************
	// Getters y setters
	//********************************************
	
	/**
	 * Retorna el certificado a verificar
	 * @return the certToVerify
	 */
	public X509Certificate getCertToVerify()
	{
		return certToVerify;
	}

	/**
	 * Establece el certificado a verificar
	 * @param certToVerify el nuevo certificado a verificar
	 */
	public void setCertToVerify(X509Certificate certToVerify) 
	{
		this.certToVerify = certToVerify;
	}

	/**
	 * Retorna el certificado emisor
	 * @return the issuerCert
	 */
	public X509Certificate getIssuerCert() 
	{
		return issuerCert;
	}

	/**
	 * Establece el certificado emisor
	 * @param issuerCert el nuevo certificado emisor
	 */
	public void setIssuerCert(X509Certificate issuerCert) 
	{
		this.issuerCert = issuerCert;
	}

	/**
	 * Retorna la URL del servidor OCSP
	 * @return the ocspServer
	 */
	public String getOcspServer() 
	{
		return ocspServer;
	}

	/**
	 * Establece la URL del servidor OCSP
	 * @param ocspServer la nueva URL del servidor OCSP
	 * @throws OcspException Se lanza una excepci�n de este tipo 
	 * 				si la URL no comienza con la cadena "http://"
	 */
	public void setOcspServer(String ocspServer) throws VerifyCertificateException 
	{
		if(!ocspServer.startsWith("http://"))
		{
			throw new VerifyCertificateException(VerifyCertificateException.getMessage("oscp.url.invalid"));
			//throw new OcspException(ERROR_OCSP_URL);
		}
		this.ocspServer = ocspServer;
	}

	/**
	 * Retorna la solicitud OCSP
	 * @return the request
	 */
	public OCSPReq getRequest() 
	{
		return request;
	}

	/**
	 * Establece la solicitud OCSP
	 * @param request la nueva solicitud OCSP
	 */
	public void setRequest(OCSPReq request) 
	{
		this.request = request;
	}

	/**
	 * Retorna la respuesta OCSP
	 * @return the response
	 */
	public OCSPResp getResponse() 
	{
		return response;
	}

	/**
	 * Establece la respuesta OCSP
	 * @param response la nueva respuesta OCSP
	 */
	public void setResponse(OCSPResp response) 
	{
		this.response = response;
	}
}