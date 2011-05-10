package org.jboss.seam.security.external.saml.api;

/**
 * Enumeration that contains the SAML protocol bindings that can be used by the
 * SAML Identity Provider and the SAML Service Provider. Refer to the SAMLv2
 * specification for details about the bindings.
 *
 * @author Marcel Kolsteren
 */
public enum SamlBinding {
    /**
     * HTTP_Redirect binding
     */
    HTTP_Redirect,

    /**
     * HTTP_Post binding
     */
    HTTP_Post
}
