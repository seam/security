package org.jboss.seam.security;

import org.picketlink.idm.api.User;

/**
 * Authenticator bean type
 *
 * @author Shane Bryzak
 */
public interface Authenticator {
    public enum AuthenticationStatus {SUCCESS, FAILURE, DEFERRED}

    void authenticate();

    void postAuthenticate();

    User getUser();

    AuthenticationStatus getStatus();
}
