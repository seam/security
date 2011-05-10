package org.jboss.seam.security.external.saml.api;

import org.jboss.seam.security.external.saml.sp.SamlExternalIdentityProvider;

/**
 * Session at the SAML Service Provider, managed by a master session at the SAML
 * Identity Provider. Other Service Providers can also participate in the same
 * master session.
 *
 * @author Marcel Kolsteren
 */
public interface SamlSpSession {

    /**
     * Gets the details of the principal, i.e. the logged in user.
     *
     * @return the principal
     */
    SamlPrincipal getPrincipal();

    /**
     * Gets the entity provider that manages the session.
     *
     * @return the entity provider
     */
    SamlExternalIdentityProvider getIdentityProvider();

}
