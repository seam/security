package org.jboss.seam.security.external.saml.api;

import java.util.List;

import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;

/**
 * Object respresenting a person that has been authenticated using SAML.
 *
 * @author Marcel Kolsteren
 */
public interface SamlPrincipal {
    /**
     * Gets the name id of the principal.
     *
     * @return the name id
     */
    SamlNameId getNameId();

    /**
     * Gets the attributes of the principal
     *
     * @return the attributes
     */
    List<AttributeType> getAttributes();
}
