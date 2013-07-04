/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.document;

import java.io.InputStream;

/**
 *
 * @author user
 */
public class Document {
    private InputStream document;

    /**
     * @return the document
     */
    public InputStream getDocument() {
        return document;
    }

    /**
     * @param document the document to set
     */
    public void setDocument(InputStream document) {
        this.document = document;
    }
    
}
