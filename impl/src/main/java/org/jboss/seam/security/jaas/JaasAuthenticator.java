package org.jboss.seam.security.jaas;

import java.io.IOException;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.Authenticator;
import org.jboss.seam.security.BaseAuthenticator;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.picketlink.idm.impl.api.PasswordCredential;

/**
 * An authenticator for authenticating with JAAS.  The jaasConfigName property
 * _must_ be configured to point to a valid JAAS configuration name, typically
 * defined in a file called login-config.xml in the application server.
 *
 * @author Shane Bryzak
 */
public
@Named
@RequestScoped
class JaasAuthenticator extends BaseAuthenticator implements Authenticator {
    private static final Logger log = Logger.getLogger(JaasAuthenticator.class);

    @Inject
    Identity identity;
    @Inject
    Credentials credentials;
    @Inject
    BeanManager manager;

    private Subject subject;

    private String jaasConfigName = null;

    public JaasAuthenticator() {
        subject = new Subject();
    }

    public void authenticate() {
        if (getJaasConfigName() == null) {
            throw new IllegalStateException("jaasConfigName cannot be null.  Please set it to a valid JAAS configuration name.");
        }

        try {
            getLoginContext().login();
            setStatus(AuthenticationStatus.SUCCESS);
        } catch (LoginException e) {
            setStatus(AuthenticationStatus.FAILURE);
            log.error("JAAS authentication failed", e);
        }
    }

    protected LoginContext getLoginContext() throws LoginException {
        return new LoginContext(getJaasConfigName(), subject,
                createCallbackHandler());
    }

    /**
     * Creates a callback handler that can handle a standard username/password
     * callback, using the credentials username and password properties
     */
    public CallbackHandler createCallbackHandler() {
        return new CallbackHandler() {
            public void handle(Callback[] callbacks)
                    throws IOException, UnsupportedCallbackException {
                for (int i = 0; i < callbacks.length; i++) {
                    if (callbacks[i] instanceof NameCallback) {
                        ((NameCallback) callbacks[i]).setName(credentials.getUsername());
                    } else if (callbacks[i] instanceof PasswordCallback) {
                        if (credentials.getCredential() instanceof PasswordCredential) {
                            PasswordCredential credential = (PasswordCredential) credentials.getCredential();
                            ((PasswordCallback) callbacks[i]).setPassword(credential.getValue() != null ?
                                    credential.getValue().toCharArray() : null);
                        }
                    } else {
                        log.warn("Unsupported callback " + callbacks[i]);
                    }
                }
            }
        };
    }

    public String getJaasConfigName() {
        return jaasConfigName;
    }

    public void setJaasConfigName(String jaasConfigName) {
        this.jaasConfigName = jaasConfigName;
    }

    public void postAuthenticate() {
    }
}
