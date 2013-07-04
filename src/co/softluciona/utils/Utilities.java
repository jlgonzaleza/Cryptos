/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package co.softluciona.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author user
 */
public class Utilities {

    public static byte[] getBytesFromFile(String path) throws Exception,
            IOException {
        File file2process = new File(path);
        InputStream is = new FileInputStream(file2process);

        long length = file2process.length();

        if (length > Integer.MAX_VALUE) {
            throw new Exception("File too long. ");
        }

        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;

        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new Exception("Could not completely read file " + path);
        }

        is.close();

        return bytes;
    }

    public static String formatDate(Date date) {
        String patron = "dd/MM/yyyy HH:mm:ss";
        DateFormat df = new SimpleDateFormat(patron);
        return df.format(date) + " H";
    }
    
    public static String formatDateDMY(Date date) {
        String patron = "dd/MM/yyyy";
        DateFormat df = new SimpleDateFormat(patron);
        return df.format(date);
    }
}
