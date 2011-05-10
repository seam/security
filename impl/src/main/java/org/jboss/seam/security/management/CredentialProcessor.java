package org.jboss.seam.security.management;

import java.util.Map;

import org.picketlink.idm.api.Credential;

/**
 * Encodes credentials to be stored in persistent storage
 *
 * @author Shane Bryzak
 */
public interface CredentialProcessor {
    /**
     * Encodes the specified credential and returns a String representation of
     * the encoded result.
     *
     * @param credential The credential to encode
     * @param options    Encoding options
     * @return The encoded credential
     */
    String encode(Credential credential, Map<String, Object> options);

    //boolean validate(Credential credential);
}
