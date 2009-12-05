package org.jboss.seam.security.callbacks;

import java.io.Serializable;

import javax.security.auth.callback.Callback;

import org.jboss.seam.security.Identity;

/**
 * This callback implementation is used to provide an instance of the Identity bean to the LoginModule
 *  
 * @author Shane Bryzak
 */
public class IdentityCallback implements Serializable, Callback
{
   private static final long serialVersionUID = 5720975438991518059L;
   
   private Identity identity;
   
   public void setIdentity(Identity identity)
   {
      this.identity = identity;
   }
   
   public Identity getIdentity()
   {
      return identity;
   }
}
