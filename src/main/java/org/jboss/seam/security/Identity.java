package org.jboss.seam.security;

import java.io.IOException;
import java.io.Serializable;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.el.ValueExpression;
import javax.enterprise.context.SessionScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.seam.security.callbacks.AuthenticatorCallback;
import org.jboss.seam.security.callbacks.IdentityCallback;
import org.jboss.seam.security.callbacks.IdentityManagerCallback;
import org.jboss.seam.security.events.AlreadyLoggedInEvent;
import org.jboss.seam.security.events.LoggedInEvent;
import org.jboss.seam.security.events.LoggedOutEvent;
import org.jboss.seam.security.events.LoginFailedEvent;
import org.jboss.seam.security.events.NotAuthorizedEvent;
import org.jboss.seam.security.events.NotLoggedInEvent;
import org.jboss.seam.security.events.PostAuthenticateEvent;
import org.jboss.seam.security.events.PreAuthenticateEvent;
import org.jboss.seam.security.events.QuietLoginEvent;
import org.jboss.seam.security.management.IdentityManager;
import org.jboss.seam.security.permission.PermissionMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * API for authorization and authentication via Seam security.
 * 
 * @author Shane Bryzak
 */
@Named
@SessionScoped
public class Identity implements Serializable
{
   private static final long serialVersionUID = 3751659008033189259L;
   
   protected static boolean securityEnabled = true;
   
   public static final String ROLES_GROUP = "Roles";
   
   Logger log = LoggerFactory.getLogger(Identity.class);

   @Inject private BeanManager manager;
   @Inject private Credentials credentials;
   @Inject private PermissionMapper permissionMapper;
   
   @Inject private IdentityManager identityManager;
   
   @Inject Instance<RequestSecurityState> requestSecurityState;
   
   private Principal principal;
   private Subject subject;
   private String jaasConfigName = null;
   private List<String> preAuthenticationRoles = new ArrayList<String>();
   
   private transient ThreadLocal<Boolean> systemOp;
   
   /**
    * Flag that indicates we are in the process of authenticating
    */
   private boolean authenticating = false;
         
   @Inject
   public void create()
   {
      subject = new Subject();
   }
   
   public static boolean isSecurityEnabled()
   {
      return securityEnabled;
   }
   
   public static void setSecurityEnabled(boolean enabled)
   {
      securityEnabled = enabled;
   }
   
   /**
    * Simple check that returns true if the user is logged in, without attempting to authenticate
    * 
    * @return true if the user is logged in
    */
   public boolean isLoggedIn()
   {
      // If there is a principal set, then the user is logged in.
      return getPrincipal() != null;
   }
   
   /**
    * Will attempt to authenticate quietly if the user's credentials are set and they haven't
    * authenticated already.  A quiet authentication doesn't throw any exceptions if authentication
    * fails.
    * 
    * @return true if the user is logged in, false otherwise
    */
   public boolean tryLogin()
   {      
      if (!authenticating && getPrincipal() == null && credentials.isSet() && 
            !requestSecurityState.get().isLoginTried())
      {
         requestSecurityState.get().setLoginTried(true);
         quietLogin();
      }
      
      return isLoggedIn();
   }

   public Principal getPrincipal()
   {
      return principal;
   }
   
   public Subject getSubject()
   {
      return subject;
   }
   
   /**
    * Performs an authorization check, based on the specified security expression.
    * 
    * @param expr The security expression to evaluate
    * @throws NotLoggedInException Thrown if the authorization check fails and
    * the user is not authenticated
    * @throws AuthorizationException Thrown if the authorization check fails and
    * the user is authenticated
    */
   // QUESTION should we add the dependency on el-api for the sake of avoiding reinstantiating the VE?
   
   // TODO redesign restrictions system to be typesafe
   /*
   public void checkRestriction(ValueExpression expression)
   {
      if (!securityEnabled)
      {
         return;
      }
      
      if (!expressions.getValue(expression, Boolean.class))
      {
         if (!isLoggedIn())
         {
            manager.fireEvent(new NotLoggedInEvent());
            
            log.debug(String.format(
               "Error evaluating expression [%s] - User not logged in", expression.getExpressionString()));
            throw new NotLoggedInException();
         }
         else
         {
            manager.fireEvent(new NotAuthorizedEvent());
            throw new AuthorizationException(String.format(
               "Authorization check failed for expression [%s]", expression.getExpressionString()));
         }
      }
   }*/
   
   /**
    * Performs an authorization check, based on the specified security expression string.
    * 
    * @param expr The security expression string to evaluate
    * @throws NotLoggedInException Thrown if the authorization check fails and
    * the user is not authenticated
    * @throws AuthorizationException Thrown if the authorization check fails and
    * the user is authenticated
    */
   
   /*
   public void checkRestriction(String expr)
   {
      if (!securityEnabled)
      {
         return;
      }
      
      checkRestriction(expressions.createValueExpression(expr, Boolean.class).toUnifiedValueExpression());
   }*/

   /**
    * Attempts to authenticate the user.  This method is distinct to the
    * authenticate() method in that it raises events in response to whether
    * authentication is successful or not.  The following events may be raised
    * by calling login():
    * 
    * org.jboss.seam.security.loginSuccessful - raised when authentication is successful
    * org.jboss.seam.security.loginFailed - raised when authentication fails
    * org.jboss.seam.security.alreadyLoggedIn - raised if the user is already authenticated
    * 
    * @return String returns "loggedIn" if user is authenticated, or null if not.
    */
   public String login()
   {
      try
      {
         if (isLoggedIn())
         {
            // If authentication has already occurred during this request via a silent login,
            // and login() is explicitly called then we still want to raise the LOGIN_SUCCESSFUL event,
            // and then return.
            if (requestSecurityState.get().isSilentLogin())
            {
               manager.fireEvent(new LoggedInEvent(principal));
               return "loggedIn";
            }
            
            manager.fireEvent(new AlreadyLoggedInEvent());
            return "loggedIn";
         }
         
         authenticate();
         
         if (!isLoggedIn())
         {
            throw new LoginException();
         }
         
         if ( log.isDebugEnabled() )
         {
            log.debug("Login successful for: " + credentials);
         }

         manager.fireEvent(new LoggedInEvent(principal));
         return "loggedIn";
      }
      catch (LoginException ex)
      {
         credentials.invalidate();
         
         if ( log.isDebugEnabled() )
         {
             log.debug("Login failed for: " + credentials, ex);
         }
         
         manager.fireEvent(new LoginFailedEvent(ex));
      }
      
      return null;
   }
   
   /**
    * Attempts a quiet login, suppressing any login exceptions and not creating
    * any faces messages. This method is intended to be used primarily as an
    * internal API call, however has been made public for convenience.
    */
   public void quietLogin()
   {
      try
      {
         manager.fireEvent(new QuietLoginEvent());
          
         // Ensure that we haven't been authenticated as a result of the EVENT_QUIET_LOGIN event
         if (!isLoggedIn())
         {
            if (credentials.isSet())
            {
               authenticate();
               
               if (isLoggedIn())
               {
                  requestSecurityState.get().setSilentLogin(true);
               }
            }
         }
      }
      catch (LoginException ex)
      {
         credentials.invalidate();
      }
   }

   /**
    * 
    * @throws LoginException
    */
   public synchronized void authenticate()
      throws LoginException
   {
      // If we're already authenticated, then don't authenticate again
      if (!isLoggedIn() && !credentials.isInvalid())
      {
         principal = null;
         subject = new Subject();
         authenticate( getLoginContext() );
      }
   }

    
   protected void authenticate(LoginContext loginContext)
      throws LoginException
   {
      try
      {
         authenticating = true;
         preAuthenticate();
         loginContext.login();
         postAuthenticate();
      }
      finally
      {
         // Set password to null whether authentication is successful or not
         credentials.setPassword(null);
         authenticating = false;
      }
   }
   
   /**
    * Clears any roles added by calling addRole() while not authenticated.
    * This method may be overridden by a subclass if different
    * pre-authentication logic should occur.
    */
   protected void preAuthenticate()
   {
      preAuthenticationRoles.clear();
      manager.fireEvent(new PreAuthenticateEvent());
   }
   
   /**
    * Extracts the principal from the subject, and populates the roles of the
    * authenticated user.  This method may be overridden by a subclass if
    * different post-authentication logic should occur.
    */
   protected void postAuthenticate()
   {
      // Populate the working memory with the user's principals
      for ( Principal p : getSubject().getPrincipals() )
      {
         if ( !(p instanceof Group))
         {
            if (principal == null)
            {
               principal = p;
               break;
            }
         }
      }
      
      if (!preAuthenticationRoles.isEmpty() && isLoggedIn())
      {
         for (String role : preAuthenticationRoles)
         {
            addRole(role);
         }
         preAuthenticationRoles.clear();
      }

      credentials.setPassword(null);
      
      manager.fireEvent(new PostAuthenticateEvent());
   }
   
   /**
    * Resets all security state and credentials
    */
   public void unAuthenticate()
   {
      principal = null;
      subject = new Subject();
      
      credentials.clear();
   }

   protected LoginContext getLoginContext() throws LoginException
   {
      if (getJaasConfigName() != null)
      {
         return new LoginContext(getJaasConfigName(), getSubject(),
                  createCallbackHandler());
      }
      
      @SuppressWarnings("unchecked")
      Bean<Configuration> configBean = (Bean<Configuration>) manager.getBeans(Configuration.class).iterator().next();
      Configuration config = (Configuration) manager.getReference(configBean, Configuration.class, manager.createCreationalContext(configBean));
      
      return new LoginContext(JaasConfiguration.DEFAULT_JAAS_CONFIG_NAME, getSubject(),
            createCallbackHandler(), config);
   }
   
   
   /**
    * Creates a callback handler that can handle a standard username/password
    * callback, using the credentials username and password properties
    */
   public CallbackHandler createCallbackHandler()
   {
      final Identity identity = this;
      final Authenticator authenticator;
      
      Set<Bean<?>> authenticators = manager.getBeans(Authenticator.class);
      if (authenticators.size() == 1)
      {
         @SuppressWarnings("unchecked")
         Bean<Authenticator> authenticatorBean = (Bean<Authenticator>) authenticators.iterator().next();
         authenticator = (Authenticator) manager.getReference(authenticatorBean, Authenticator.class, manager.createCreationalContext(authenticatorBean));
      }
      else if (authenticators.size() > 1)
      {
         throw new IllegalStateException("More than one Authenticator bean found - please ensure " +
               "only one Authenticator implementation is provided");
      }
      else
      {
         authenticator = null;
      }
      
      return new CallbackHandler()
      {
         public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException
         {
            for (int i=0; i < callbacks.length; i++)
            {
               if (callbacks[i] instanceof NameCallback)
               {
                  ( (NameCallback) callbacks[i] ).setName(credentials.getUsername());
               }
               else if (callbacks[i] instanceof PasswordCallback)
               {
                  ( (PasswordCallback) callbacks[i] ).setPassword( credentials.getPassword() != null ?
                           credentials.getPassword().toCharArray() : null );
               }
               else if (callbacks[i] instanceof IdentityCallback)
               {
                  ((IdentityCallback ) callbacks[i]).setIdentity(identity);
               }
               else if (callbacks[i] instanceof AuthenticatorCallback)
               {
                  ((AuthenticatorCallback) callbacks[i]).setAuthenticator(authenticator);
               }
               else if (callbacks[i] instanceof IdentityManagerCallback)
               {
                  ((IdentityManagerCallback) callbacks[i]).setIdentityManager(identityManager);
               }
               else
               {
                  log.warn("Unsupported callback " + callbacks[i]);
               }
            }
         }
      };
   }
   
   public void logout()
   {
      if (isLoggedIn())
      {
         LoggedOutEvent loggedOutEvent = new LoggedOutEvent(principal);
         unAuthenticate();
         
         // TODO - invalidate the session
         // Session.instance().invalidate();
         
         manager.fireEvent(loggedOutEvent);
      }
   }

   /**
    * Checks if the authenticated user is a member of the specified role.
    * 
    * @param role String The name of the role to check
    * @return boolean True if the user is a member of the specified role
    */
   public boolean hasRole(String role)
   {
      if (!securityEnabled) return true;
      if (systemOp != null && Boolean.TRUE.equals(systemOp.get())) return true;
      
      tryLogin();
      
      for ( Group sg : getSubject().getPrincipals(Group.class) )
      {
         if ( ROLES_GROUP.equals( sg.getName() ) )
         {
            return sg.isMember( new Role(role) );
         }
      }
      return false;
   }
   
   /**
    * Adds a role to the authenticated user.  If the user is not logged in,
    * the role will be added to a list of roles that will be granted to the
    * user upon successful authentication, but only during the authentication
    * process.
    * 
    * @param role The name of the role to add
    */
   public boolean addRole(String role)
   {
      if (role == null || "".equals(role)) return false;
      
      if (!isLoggedIn())
      {
         preAuthenticationRoles.add(role);
         return false;
      }
      else
      {
         for ( Group sg : getSubject().getPrincipals(Group.class) )
         {
            if ( ROLES_GROUP.equals( sg.getName() ) )
            {
               return sg.addMember(new Role(role));
            }
         }
                  
         SimpleGroup roleGroup = new SimpleGroup(ROLES_GROUP);
         roleGroup.addMember(new Role(role));
         getSubject().getPrincipals().add(roleGroup);
         return true;
      }
   }

   /**
    * Removes a role from the authenticated user
    * 
    * @param role The name of the role to remove
    */
   public void removeRole(String role)
   {
      for ( Group sg : getSubject().getPrincipals(Group.class) )
      {
         if ( ROLES_GROUP.equals( sg.getName() ) )
         {
            Enumeration<?> e = sg.members();
            while (e.hasMoreElements())
            {
               Principal member = (Principal) e.nextElement();
               if (member.getName().equals(role))
               {
                  sg.removeMember(member);
                  break;
               }
            }

         }
      }
   }
   
   /**
    * Checks that the current authenticated user is a member of
    * the specified role.
    * 
    * @param role String The name of the role to check
    * @throws AuthorizationException if the authenticated user is not a member of the role
    */
   public void checkRole(String role)
   {
      tryLogin();
      
      if ( !hasRole(role) )
      {
         if ( !isLoggedIn() )
         {
            manager.fireEvent(new NotLoggedInEvent());
            throw new NotLoggedInException();
         }
         else
         {
            manager.fireEvent(new NotAuthorizedEvent());
            throw new AuthorizationException(String.format(
                  "Authorization check failed for role [%s]", role));
         }
      }
   }
   
   public void checkPermission(Object target, String action)
   {
      if (systemOp != null && Boolean.TRUE.equals(systemOp.get())) return;
      
      tryLogin();
      
      if ( !hasPermission(target, action) )
      {
         if ( !isLoggedIn() )
         {
            manager.fireEvent(new NotLoggedInEvent());
            throw new NotLoggedInException();
         }
         else
         {
            manager.fireEvent(new NotAuthorizedEvent());
            throw new AuthorizationException(String.format(
                  "Authorization check failed for permission[%s,%s]", target, action));
         }
      }
   }
   
   public void filterByPermission(Collection<?> collection, String action)
   {
      permissionMapper.filterByPermission(collection, action);
   }
   
   public boolean hasPermission(Object target, String action)
   {
      if (!securityEnabled) return true;
      if (systemOp != null && Boolean.TRUE.equals(systemOp.get())) return true;
      if (permissionMapper == null) return false;
      if (target == null) return false;
      
      return permissionMapper.resolvePermission(target, action);
   }
   
   /**
    * Evaluates the specified security expression, which must return a boolean
    * value.
    * 
    * @param expr String The expression to evaluate
    * @return boolean The result of the expression evaluation
    */
   /*
   protected boolean evaluateExpression(String expr)
   {
      return expressions.createValueExpression(expr, Boolean.class).getValue();
   }*/
   
   public String getJaasConfigName()
   {
      return jaasConfigName;
   }
   
   public void setJaasConfigName(String jaasConfigName)
   {
      this.jaasConfigName = jaasConfigName;
   }
   
   public synchronized void runAs(RunAsOperation operation)
   {
      Principal savedPrincipal = getPrincipal();
      Subject savedSubject = getSubject();
      
      try
      {
         principal = operation.getPrincipal();
         subject = operation.getSubject();
         
         if (systemOp == null)
         {
            systemOp = new ThreadLocal<Boolean>();
         }
         
         systemOp.set(operation.isSystemOperation());
         
         operation.execute();
      }
      finally
      {
         systemOp.set(false);
         principal = savedPrincipal;
         subject = savedSubject;
      }
   }
}
