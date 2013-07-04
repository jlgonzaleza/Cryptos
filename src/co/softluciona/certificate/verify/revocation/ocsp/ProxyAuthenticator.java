package co.softluciona.certificate.verify.revocation.ocsp;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * Configuraci�n del proxy para poder acceder al servidor OSCP.
 * @author jhon.gonzalez
 *
 */
public class ProxyAuthenticator extends Authenticator
{
	private String login;
	private String password;
	
	public ProxyAuthenticator(String login, String password ) 
	{
		this.login = login;
		this.password = password;
	}
	
	public PasswordAuthentication getPasswordAuthentication()
	{
		return new PasswordAuthentication(login, password.toCharArray());
	}

	public String getLogin() 
	{
		return login;
	}

	public String getPassword() 
	{
		return password;
	}

	public void setLogin(String login) 
	{
		this.login = login;
	}

	public void setPassword(String password) 
	{
		this.password = password;
	}

}
