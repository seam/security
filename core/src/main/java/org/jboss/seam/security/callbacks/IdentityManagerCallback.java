package org.jboss.seam.security.callbacks;

import java.io.Serializable;

import javax.security.auth.callback.Callback;

import org.jboss.seam.security.management.IdentityManager;

/**
 * This callback implementation is used to provide an instance of the IdentityManager bean to the LoginModule
 * 
 * @author Shane Bryzak
 */
public class IdentityManagerCallback implements Serializable, Callback
{
   private static final long serialVersionUID = 8430300053672194472L;
   
   private IdentityManager identityManager;
   
   public IdentityManager getIdentityManager()
   {
      return identityManager;
   }

   public void setIdentityManager(IdentityManager identityManager)
   {
      this.identityManager = identityManager;
   }
}
