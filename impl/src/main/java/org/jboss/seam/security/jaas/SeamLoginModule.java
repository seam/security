package org.jboss.seam.security.jaas;

import static org.jboss.seam.security.Identity.ROLES_GROUP;

import java.security.acl.Group;
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

import org.jboss.seam.security.SimpleGroup;
import org.jboss.seam.security.SimplePrincipal;
import org.jboss.seam.security.callbacks.AuthenticatorCallback;
import org.jboss.seam.security.callbacks.IdentityCallback;
import org.jboss.seam.security.callbacks.IdentityManagerCallback;
import org.jboss.seam.security.management.IdentityManager;

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
      
      Group roleGroup = null;
      
      for ( Group g : subject.getPrincipals(Group.class) )      
      {
         if ( ROLES_GROUP.equalsIgnoreCase( g.getName() ) )
         {
            roleGroup = g;
            break;
         }
      }

      if (roleGroup == null) roleGroup = new SimpleGroup(ROLES_GROUP);

      for (String role : roles)
      {
         roleGroup.addMember(new SimplePrincipal(role));
      }
      
      subject.getPrincipals().add(roleGroup);
      
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
         if (identityManager != null && identityManager.isEnabled())
         {            
            boolean success = identityManager.authenticate(username, 
                  new String(cbPassword.getPassword()));
            
            if (success)
            {
               for (String role : identityManager.getImpliedRoles(username))
               {
                  idCallback.getIdentity().addRole(role);
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
