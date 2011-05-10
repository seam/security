package org.jboss.seam.security;

import java.io.Serializable;
import java.rmi.server.UID;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.events.QuietLoginEvent;
import org.jboss.seam.security.util.Base64;
import org.picketlink.idm.api.Role;

/**
 * Remember-me functionality is provided by this class, in two different flavours.  The first mode
 * provides username-only persistence, and is considered to be secure as the user (or their browser)
 * is still required to provide a password.  The second mode provides an auto-login feature, however
 * is NOT considered to be secure and is vulnerable to XSS attacks compromising the user's account.
 * <p/>
 * Use the auto-login mode with caution!
 *
 * @author Shane Bryzak
 */
@Named
@SessionScoped
public class RememberMe implements Serializable {
    private static final long serialVersionUID = 2242379431576068199L;

    public enum Mode {disabled, usernameOnly, autoLogin}

    @Inject
    BeanManager manager;
    @Inject
    Identity identity;
    @Inject
    IdentityImpl identityImpl;
    @Inject
    CredentialsImpl credentials;

    // Heaps of stuff commented out here because we need to add generic cookie support

    //private ManagedCookie usernameSelector;
    //private ManagedCookie tokenSelector;

    private TokenStore tokenStore;

    private boolean enabled;

    //private int cookieMaxAge = ManagedCookie.DEFAULT_MAX_AGE;

    private boolean autoLoggedIn;

    private Random random = new Random(System.currentTimeMillis());

    private Mode mode = Mode.usernameOnly;

    public RememberMe() {
    }

    /*
    public
    @Inject
    void create()
    {
       if (mode.equals(Mode.usernameOnly))
       {
          usernameSelector = (ManagedCookie) BeanManagerHelper.getInstanceByType(manager, ManagedCookie.class);
          usernameSelector.setCookieName("org.jboss.seam.security.username");
          usernameSelector.setCookieEnabled(enabled);
       }
       else if (mode.equals(Mode.autoLogin))
       {
          tokenSelector = (ManagedCookie) BeanManagerHelper.getInstanceByType(manager, ManagedCookie.class);
          tokenSelector.setCookieName("org.jboss.seam.security.authtoken");
          tokenSelector.setCookieEnabled(enabled);

          // Default to JpaTokenStore
          if (tokenStore == null)
          {
             tokenStore = BeanManagerHelper.getInstanceByType(manager,JpaTokenStore.class);
          }
       }
    }

    public void initCredentials(@Observes CredentialsInitializedEvent event)
    {
       // FIXME use the context path as the cookie path
       // String cookiePath = getCookiePath();
       String cookiePath = "/";

       if (mode.equals(Mode.usernameOnly))
       {
          if (cookiePath != null)
          {
             usernameSelector.setCookiePath(cookiePath);
          }

          String username = usernameSelector.getCookieValue();
          if (username!=null)
          {
             setEnabled(true);
             event.getCredentials().setUsername(username);
          }
       }
       else if (mode.equals(Mode.autoLogin))
       {
          if (cookiePath != null)
          {
             tokenSelector.setCookiePath(cookiePath);
          }

          String token = tokenSelector.getCookieValue();
          if (token != null)
          {
             setEnabled(true);

             DecodedToken decoded = new DecodedToken(token);

             if (tokenStore.validateToken(decoded.getUsername(), decoded.getValue()))
             {
                event.getCredentials().setUsername(decoded.getUsername());
                event.getCredentials().setPassword(decoded.getValue());
             }
             else
             {
                // Have we been compromised? Just in case, invalidate all authentication tokens
                tokenStore.invalidateAll(decoded.getUsername());
             }
          }
       }
    }*/

    public void quietLogin(@Observes QuietLoginEvent event) {
        if (mode.equals(Mode.autoLogin) && isEnabled()) {
            final String username = credentials.getUsername();
            final BoolWrapper userEnabled = new BoolWrapper();
            final List<Role> roles = new ArrayList<Role>();

            // Double check our credentials again
            if (tokenStore.validateToken(username, credentials.getPassword())) {
                identityImpl.runAs(new RunAsOperation(true) {
                    @Override
                    public void execute() {
                        /*if (identityManager.isUserEnabled(username))
                        {
                           userEnabled.value = true;

                           for (Role role : identityManager.getUserRoles(username))
                           {
                              roles.add(role);
                           }
                        }*/
                    }
                });

                if (userEnabled.value) {
                    identityImpl.unAuthenticate();
                    identityImpl.preAuthenticate();

                    // populate the roles
                    for (Role role : roles) {
                        identity.addRole(role.getRoleType().getName(),
                                role.getGroup().getName(), role.getGroup().getGroupType());
                    }

                    // Set the principal
                    // identity.getSubject().getPrincipals().add(new SimplePrincipal(username));
                    identityImpl.postAuthenticate();

                    autoLoggedIn = true;
                }
            }
        }
    }
    /*
    public void postAuthenticate(@Observes PostAuthenticateEvent event)
    {
       if (mode.equals(Mode.usernameOnly))
       {
          if ( !enabled )
          {
             usernameSelector.clearCookieValue();
          }
          else
          {
             usernameSelector.setCookieMaxAge(cookieMaxAge);
             usernameSelector.setCookieValueIfEnabled( credentials.getUsername() );
          }
       }
       else if (mode.equals(Mode.autoLogin))
       {
          DecodedToken decoded = new DecodedToken(tokenSelector.getCookieValue());

          // Invalidate the current token (if it exists) whether enabled or not
          if (decoded.getUsername() != null)
          {
             tokenStore.invalidateToken(decoded.getUsername(), decoded.getValue());
          }

          if ( !enabled )
          {
             tokenSelector.clearCookieValue();
          }
          else
          {
             String value = generateTokenValue();
             tokenStore.createToken(identity.getPrincipal().getName(), value);
             tokenSelector.setCookieEnabled(enabled);
             tokenSelector.setCookieMaxAge(cookieMaxAge);
             tokenSelector.setCookieValueIfEnabled(encodeToken(identity.getPrincipal().getName(), value));
          }
       }
    }
    */

    /*
    public void loggedOut(@Observes LoggedOutEvent event)
    {
       if (mode.equals(Mode.autoLogin))
       {
          tokenSelector.clearCookieValue();
       }
    }*/

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /*
    public void setEnabled(boolean enabled)
    {
       if (this.enabled != enabled)
       {
          this.enabled = enabled;
          // selector is null during component initialization (setup handled in @Create method)
          if (usernameSelector != null && mode.equals(Mode.usernameOnly))
          {
             usernameSelector.setCookieEnabled(enabled);
          }
          // selector is null during component initialization (setup handled in @Create method)
          else if (tokenSelector != null && mode.equals(Mode.autoLogin))
          {
             tokenSelector.setCookieEnabled(enabled);
          }
       }
    }*/

    /*
    public int getCookieMaxAge() {
        return cookieMaxAge;
    }

    public void setCookieMaxAge(int cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }*/

    public TokenStore getTokenStore() {
        return tokenStore;
    }

    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    /**
     * A flag that an application can use to protect sensitive operations if the user has been
     * auto-authenticated.
     */
    public boolean isAutoLoggedIn() {
        return autoLoggedIn;
    }

    protected String generateTokenValue() {
        StringBuilder sb = new StringBuilder();
        sb.append(new UID().toString());
        sb.append(":");
        sb.append(random.nextLong());
        return sb.toString();
    }

    protected String encodeToken(String username, String value) {
        StringBuilder sb = new StringBuilder();
        sb.append(username);
        sb.append(":");
        sb.append(value);
        return Base64.encodeBytes(sb.toString().getBytes());
    }

    /**
     * I hate these hacks...
     */
    private class BoolWrapper {
        boolean value;
    }

    /*
    private class DecodedToken
    {
       private String username;
       private String value;

       public DecodedToken(String cookieValue)
       {
          if (cookieValue != null)
          {
             try
             {
                String decoded = new String(Base64.decode(cookieValue));
                username = decoded.substring(0, decoded.indexOf(':'));
                value = decoded.substring(decoded.indexOf(':') + 1);
             }
             catch (Exception ex)
             {
                // intentionally swallow
             }
          }
       }

       public String getUsername()
       {
          return username;
       }

       public String getValue()
       {
          return value;
       }
    }*/
}
