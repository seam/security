package org.jboss.seam.security;

/**
 * Seam implementation of the PicketLink CredentialType interface.  A
 * CredentialType represents a type of credential, e.g. password, certificate, etc.
 *
 * @author Shane Bryzak
 */
public class CredentialType implements org.picketlink.idm.api.CredentialType {
    private String name;

    public CredentialType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
