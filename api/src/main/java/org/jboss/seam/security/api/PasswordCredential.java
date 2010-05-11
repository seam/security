package org.jboss.seam.security.api;

/**
 * Seam implementation of the PicketLink Credential interface
 * 
 * @author Shane Bryzak
 */
public class PasswordCredential implements org.picketlink.idm.api.Credential
{
   private static final CredentialType CREDENTIAL_TYPE = new CredentialType("password");
   
   public org.picketlink.idm.api.CredentialType getType()
   {
      return CREDENTIAL_TYPE;
   }

}
