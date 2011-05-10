package org.jboss.seam.security;

import javax.enterprise.context.RequestScoped;

/**
 * Contains the authentication state of the current request
 *
 * @author Shane Bryzak
 */
@RequestScoped
public class RequestSecurityState {
    private boolean silentLogin;
    private boolean loginTried;

    public boolean isSilentLogin() {
        return silentLogin;
    }

    public void setSilentLogin(boolean silentLogin) {
        this.silentLogin = silentLogin;
    }

    public boolean isLoginTried() {
        return loginTried;
    }

    public void setLoginTried(boolean loginTried) {
        this.loginTried = loginTried;
    }
}
