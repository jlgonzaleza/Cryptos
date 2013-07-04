package co.softluciona.certificate.verify.revocation.ocsp;

import java.util.Date;

/**
 * Respuesta de la verificaci�n por OSCP
 * @author jhon.gonzalez
 *
 */
public class OcspResponse {
	/**
	 * Respuesta en texto de la validaci�n por OSCP.
	 */
	private String message;
	/**
	 * Indica si el certificado fue revocado.
	 */
	private boolean revoke;
	/**
	 * Indica que el estado del certificado fue desconocido.
	 */
	private boolean unknow;
	/**
	 * Indica que el certificado es v�lido.
	 */
	private boolean good;
	/**
	 * Si el certificado fu� revocado, se guarda la fecha de revocaci�n en este par�metro.
	 */
	private Date revokeDate;
	
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public boolean isRevoke() {
		return revoke;
	}
	public void setRevoke(boolean revoke) {
		this.revoke = revoke;
	}
	public boolean isUnknow() {
		return unknow;
	}
	public void setUnknow(boolean unknow) {
		this.unknow = unknow;
	}
	public boolean isGood() {
		return good;
	}
	public void setGood(boolean good) {
		this.good = good;
	}
	public Date getRevokeDate() {
		return revokeDate;
	}
	public void setRevokeDate(Date revokeDate) {
		this.revokeDate = revokeDate;
	}

}
