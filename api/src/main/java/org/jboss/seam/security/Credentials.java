package org.jboss.seam.security;

import org.picketlink.idm.api.Credential;

/**
 * Represents the credentials the current user will use to authenticate
 *
 * @author Shane Bryzak
 */
public interface Credentials {
    String getUsername();

    void setUsername(String username);

    Credential getCredential();

    void setCredential(Credential credential);

    boolean isSet();

    boolean isInvalid();

    void invalidate();

    void clear();

}
