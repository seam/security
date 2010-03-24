package org.jboss.seam.security.management;

/**
 * Thrown when an exception is encountered during account creation. 
 *  
 * @author Shane Bryzak
 */
public class IdentityManagementException extends RuntimeException
{
   private static final long serialVersionUID = -8682163627028954352L;

   public IdentityManagementException(String message)
   {
      super(message);
   }
   
   public IdentityManagementException(String message, Throwable cause)
   {
      super(message, cause);
   }
}
