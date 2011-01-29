package org.jboss.seam.security.management;

import java.util.Collection;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.UserImpl;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;
import org.picketlink.idm.common.exception.FeatureNotSupportedException;
import org.picketlink.idm.common.exception.IdentityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticates using Identity Management
 * 
 * @author Shane Bryzak
 *
 */
public @Model class IdmAuthenticator extends BaseAuthenticator implements Authenticator
{
   Logger log = LoggerFactory.getLogger(IdmAuthenticator.class);
   
   @Inject IdentitySession identitySession;
   @Inject Credentials credentials;
   @Inject Identity identity;
   
   public void authenticate()
   {
      if (identitySession != null)
      {            
         User u = new UserImpl(credentials.getUsername()); 
         
         try
         {
            boolean success = identitySession.getAttributesManager().validateCredentials(
                  u, new Credential[] {credentials.getCredential()});
            
            if (success)
            {
               Collection<RoleType> roleTypes = identitySession.getRoleManager()
                   .findUserRoleTypes(u);
               
               for (RoleType roleType : roleTypes)
               {
                  for (Role role : identitySession.getRoleManager().findRoles(u, roleType))
                  {
                     identity.addRole(role.getRoleType().getName(), 
                           role.getGroup().getName(), role.getGroup().getGroupType());   
                  }
               }
               setStatus(AuthenticationStatus.SUCCESS);
            }
         }
         catch (IdentityException ex)
         {
            log.error("Authentication error", ex);
         }
         catch (FeatureNotSupportedException ex)
         {
            log.error("Authentication error", ex);
         }         
      }
      
      setStatus(AuthenticationStatus.FAILURE);
   }
   
   public void postAuthenticate() {}

}
