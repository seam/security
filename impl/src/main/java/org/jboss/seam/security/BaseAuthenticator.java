package org.jboss.seam.security;

import org.picketlink.idm.api.User;

/**
 * Abstract implementation of Authenticator which provides basic features
 *
 * @author Shane Bryzak
 */
public abstract class BaseAuthenticator implements Authenticator {
    private AuthenticationStatus status;
    private User user;

    public AuthenticationStatus getStatus() {
        return status;
    }

    public void setStatus(AuthenticationStatus status) {
        this.status = status;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void postAuthenticate() {
        // No-op, override if any post-authentication processing is required.
    }
}
