package org.jboss.seam.security.management;

import java.util.Map;

/**
 * Encodes user passwords for persistent storage
 * 
 * @author Shane Bryzak
 *
 */
public interface PasswordEncoder
{
   /**
    * Encodes the specified password
    * 
    * @param password
    * @return
    */
   String encodePassword(String password);
   
   /**
    * Encodes the specified password using the provided options
    * 
    * @param password
    * @param options
    * @return
    */
   String encodePassword(String password, Map options);
}
