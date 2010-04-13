package org.jboss.seam.security.callbacks;

import java.io.Serializable;

import javax.security.auth.callback.Callback;

import org.jboss.seam.security.Authenticator;

/**
 * This callback implementation is used to provide an instance of the Authenticator bean to the LoginModule
 * 
 * @author Shane Bryzak
 */
public class AuthenticatorCallback implements Serializable, Callback
{
   private static final long serialVersionUID = -6186364148255506167L;
   
   private Authenticator authenticator;
   
   public Authenticator getAuthenticator()
   {
      return authenticator;
   }
   
   public void setAuthenticator(Authenticator authenticator)
   {
      this.authenticator = authenticator;
   }
}
