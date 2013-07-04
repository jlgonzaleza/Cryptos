/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.certificate.verify.exception;

import java.util.ResourceBundle;

/**
 *
 * @author user
 */
public class VerifyCertificateException extends Exception{
    private static ResourceBundle resourceBundle = ResourceBundle.getBundle( "co.softluciona.messages.certificate" );
    
    public static String getMessage(String codeName){
       return  resourceBundle.getString(codeName);
    }
    
     public VerifyCertificateException(String message){
        super(message);        
        
        
    }
    
    public VerifyCertificateException(String message,Exception e){
        super(message,e);
    }
    
}
