package org.jboss.seam.security.management;

import java.util.Map;

import org.picketlink.idm.api.Credential;

/**
 * Default password encoder, creates password hashes.
 *
 * @author Shane Bryzak
 */
public class PasswordHashEncoder implements CredentialProcessor {
    private String passwordHash;
    private int passwordIterations = 1000;

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public int getPasswordIterations() {
        return passwordIterations;
    }

    public void setPasswordIterations(int passwordIterations) {
        this.passwordIterations = passwordIterations;
    }

    public String encode(Credential credential, Map<String, Object> options) {

        // TODO Auto-generated method stub
        return null;
    }
}
