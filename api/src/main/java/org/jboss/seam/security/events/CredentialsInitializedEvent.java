package org.jboss.seam.security.events;

import org.jboss.seam.security.Credentials;

/**
 * This event is raised when credentials are initialized
 *
 * @author Shane Bryzak
 */
public class CredentialsInitializedEvent {
    private Credentials credentials;

    public CredentialsInitializedEvent(Credentials credentials) {
        this.credentials = credentials;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    public void setCredentials(Credentials credentials) {
        this.credentials = credentials;
    }
}
