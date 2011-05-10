package org.jboss.seam.security.external.saml.api;

/**
 * Name identifying a subject (person) that has been authenticated using SAML.
 * For details, refer to section 2.2 of the document 'Assertions and Protocols
 * for the OASIS 3 Security Assertion Markup Language (SAML) V2.0' .
 *
 * @author Marcel Kolsteren
 */
public interface SamlNameId {
    /**
     * The actual name
     *
     * @return the name (not null)
     */
    String getValue();

    /**
     * A URI reference representing the classification of string-based identifier
     * information.
     *
     * @return an URI reference, or null if the format is unspecified
     */
    String getFormat();

    /**
     * The security or administrative domain that qualifies the identifier. This
     * attribute provides a means to federate identifiers from disparate user
     * stores without collision.
     *
     * @return the qualifier, or null if the name is unqualified
     */
    String getQualifier();
}
