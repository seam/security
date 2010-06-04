package org.jboss.seam.security;

import javax.enterprise.context.RequestScoped;


/**
 * Seam implementation of the PicketLink Credential interface
 * 
 * @author Shane Bryzak
 */
@RequestScoped
public class PasswordCredential implements org.picketlink.idm.api.Credential
{
   private static final CredentialType CREDENTIAL_TYPE = new CredentialType("password");
   
   private String password;
   
   public PasswordCredential(String password)
   {
      this.password = password;
   }
   
   public org.picketlink.idm.api.CredentialType getType()
   {
      return CREDENTIAL_TYPE;
   }

   public String getPassword()
   {
      return password;
   }
}
