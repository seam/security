package org.jboss.seam.security;

/**
 * Thrown when an authenticated user has insufficient rights to carry out an action.
 * 
 * @author Shane Bryzak
 */
public class AuthorizationException extends SecurityException
{ 
   private static final long serialVersionUID = -981091398588455903L;

   public AuthorizationException(String message)
   {
      super(message);
   }
}
