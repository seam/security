package org.jboss.seam.security.external.saml;

/**
 * @author Marcel Kolsteren
 */
public enum SamlRequestOrResponse {
    REQUEST, RESPONSE;

    public boolean isRequest() {
        return this == REQUEST;
    }

    public boolean isResponse() {
        return this == RESPONSE;
    }
}
