package org.jboss.seam.security;

/**
 * Authenticator bean type
 *  
 * @author Shane Bryzak
 */
public interface Authenticator
{
   public enum AuthStatus { SUCCESS, FAILURE, DEFERRED }
   
   AuthStatus authenticate();
}
