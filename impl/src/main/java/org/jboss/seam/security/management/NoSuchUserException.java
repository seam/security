package org.jboss.seam.security.management;

/**
 * Thrown when an operation is attempted on a non-existent user.  
 * 
 * @author Shane Bryzak
 */
public class NoSuchUserException extends RuntimeException
{
   private static final long serialVersionUID = -6117983356287782094L;

   public NoSuchUserException(String message)
   {
      super(message);
   }
   
   public NoSuchUserException(String message, Throwable cause)
   {
      super(message, cause);
   }
}
