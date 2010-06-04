package org.jboss.seam.security.jaas;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.seam.security.PasswordCredential;
import org.jboss.seam.security.SimplePrincipal;
import org.jboss.seam.security.callbacks.AuthenticatorCallback;
import org.jboss.seam.security.callbacks.IdentityCallback;
import org.jboss.seam.security.callbacks.IdentityManagerCallback;
import org.jboss.seam.security.management.IdentityManager;
import org.picketlink.idm.api.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs authentication using a Seam component or Identity Management
 * 
 * @author Shane Bryzak
 */
public class SeamLoginModule implements LoginModule
{   
   private Logger log = LoggerFactory.getLogger(SeamLoginModule.class);
   
   protected Set<String> roles = new HashSet<String>();
   
   protected Subject subject;
   protected Map<String,?> options;
   protected CallbackHandler callbackHandler;
   
   protected String username;
   
   public boolean abort() throws LoginException
   {
      return true;
   }

   public boolean commit() throws LoginException
   {        
      subject.getPrincipals().add(new SimplePrincipal(username));
      return true;
   }

   public void initialize(Subject subject, CallbackHandler callbackHandler,
         Map<String, ?> sharedState, Map<String, ?> options)
   {
      this.subject = subject;
      this.options = options;
      this.callbackHandler = callbackHandler;
   }

   public boolean login() 
      throws LoginException
   {      
      PasswordCallback cbPassword = null; 
      try
      {
         NameCallback cbName = new NameCallback("Enter username");
         cbPassword = new PasswordCallback("Enter password", false);
         
         IdentityCallback idCallback = new IdentityCallback();
         AuthenticatorCallback authCallback = new AuthenticatorCallback();
         IdentityManagerCallback idmCallback = new IdentityManagerCallback();
      
         // Get the username, password and identity from the callback handler
         callbackHandler.handle(new Callback[] { cbName, cbPassword, idCallback, authCallback, idmCallback });
         
         username = cbName.getName();
         
         // If an authenticator method has been specified, use that to authenticate
         if (authCallback.getAuthenticator() != null)
         {
            return authCallback.getAuthenticator().authenticate();
         }
                  
         // Otherwise if identity management is enabled, use it.
         IdentityManager identityManager = idmCallback.getIdentityManager();
         if (identityManager != null)
         {            
            boolean success = identityManager.authenticate(username, 
                  new PasswordCredential(new String(cbPassword.getPassword())));
            
            if (success)
            {
               for (Role role : identityManager.getImpliedRoles(username))
               {
                  idCallback.getIdentity().addRole(role.getRoleType().getName(), 
                        role.getGroup().getName(), role.getGroup().getGroupType());
               }
            }
            
            return success;
         }
         else
         {
            log.error("No Authenticator bean found.");
            throw new LoginException("No Authenticator bean found");
         }
      }
      catch (Exception ex)
      {
         log.error("Error logging in", ex);
         LoginException le = new LoginException(ex.getMessage());
         le.initCause(ex);
         throw le;
      }      
      finally
      {
         cbPassword.clearPassword();
      }
   }

   public boolean logout() throws LoginException
   {
      return true;
   }
}
