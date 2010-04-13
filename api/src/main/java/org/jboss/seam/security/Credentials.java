package org.jboss.seam.security;

/**
 * Represents the credentials the current user will use to authenticate
 * 
 * @author Shane Bryzak
 *
 */
public interface Credentials
{
   String getUsername();
   
   void setUsername(String username);
   
   String getPassword();
   
   void setPassword(String password);
   
   boolean isSet();
   
   boolean isInvalid();
   
   void invalidate();
   
   void clear();

}
