package co.softluciona.certificate.verify.exception;

import java.util.ResourceBundle;

public class NotValidateException extends Exception{
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static ResourceBundle resourceBundle = ResourceBundle.getBundle( "co.softluciona.messages.certificate" );
    
    public static String getMessage(String codeName){
       return  resourceBundle.getString(codeName);
    }
    
     public NotValidateException(String message){
        super(message);        
        
        
    }
    
    public NotValidateException(String message,Exception e){
        super(message,e);
    }
    
}