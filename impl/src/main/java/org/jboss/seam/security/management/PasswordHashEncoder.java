package org.jboss.seam.security.management;

import java.util.Map;

/**
 * Default password encoder, creates password hashes.
 * 
 * @author Shane Bryzak
 *
 */
public class PasswordHashEncoder implements PasswordEncoder
{
   private String passwordHash;
   private int passwordIterations = 1000;
   
   public String getPasswordHash()
   {
      return passwordHash;
   }
   
   public void setPasswordHash(String passwordHash)
   {
      this.passwordHash = passwordHash;
   }
   
   public int getPasswordIterations()
   {
      return passwordIterations;
   }
   
   public void setPasswordIterations(int passwordIterations)
   {
      this.passwordIterations = passwordIterations;
   }
   
   public String encodePassword(String password)
   {
      return encodePassword(password, null);
   }
   
   public String encodePassword(String password, Map options)
   {
      return null;
   }
}
