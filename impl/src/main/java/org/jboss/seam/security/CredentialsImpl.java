package org.jboss.seam.security;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.events.CredentialsInitializedEvent;
import org.jboss.seam.security.events.CredentialsUpdatedEvent;
import org.jboss.seam.security.events.LoginFailedEvent;
import org.picketlink.idm.api.Credential;
import org.picketlink.idm.impl.api.PasswordCredential;

/**
 * The default Credentials implementation.  This implementation allows for a
 * username and plain text password to be set, and uses the PasswordCredential
 * implementation of the Credential interface for authentication.
 *
 * @author Shane Bryzak
 */
public
@Named("credentials")
@SessionScoped
class CredentialsImpl implements Credentials, Serializable {
    private static final long serialVersionUID = -2271248957776488426L;

    @Inject
    BeanManager manager;

    private String username;
    private Credential credential;

    private boolean invalid;

    private boolean initialized;

    public CredentialsImpl() {
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    public String getUsername() {
        if (!isInitialized()) {
            setInitialized(true);
            manager.fireEvent(new CredentialsInitializedEvent(this));
        }

        return username;
    }

    public Credential getCredential() {
        return credential;
    }

    public void setCredential(Credential credential) {
        this.credential = credential;
    }

    public void setUsername(String username) {
        if (this.username != username && (this.username == null || !this.username.equals(username))) {
            this.username = username;
            invalid = false;
            manager.fireEvent(new CredentialsUpdatedEvent());
        }
    }

    public String getPassword() {
        return credential != null && credential instanceof PasswordCredential ?
                ((PasswordCredential) credential).getValue() : null;
    }

    public void setPassword(String password) {
        if (this.credential == null) {
            this.credential = new PasswordCredential(password);
        } else if (this.credential != null && this.credential instanceof PasswordCredential &&
                ((PasswordCredential) this.credential).getValue() != password &&
                ((PasswordCredential) this.credential).getValue() == null ||
                !((PasswordCredential) this.credential).getValue().equals(password)) {
            this.credential = new PasswordCredential(password);
            invalid = false;
            manager.fireEvent(new CredentialsUpdatedEvent());
        }
    }

    public boolean isSet() {
        return getUsername() != null && this.credential != null &&
                ((PasswordCredential) this.credential).getValue() != null;
    }

    public boolean isInvalid() {
        return invalid;
    }

    public void invalidate() {
        invalid = true;
    }

    public void clear() {
        username = null;
        this.credential = null;
        initialized = false;
    }

    public void loginFailed(@Observes LoginFailedEvent event) {
        invalidate();
    }

    @Override
    public String toString() {
        return "Credentials[" + username + "]";
    }
}
