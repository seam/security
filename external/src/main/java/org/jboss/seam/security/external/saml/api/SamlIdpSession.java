package org.jboss.seam.security.external.saml.api;

import java.util.Set;

import org.jboss.seam.security.external.saml.idp.SamlExternalServiceProvider;

/**
 * Session managed by a SAML Identity Provider (IDP). Multiple Service Providers
 * (SPs) can take part in the session. The session can be terminated as a whole,
 * for all parties involved, by initiating a SAML single logout (either by the
 * IDP or by a SP).
 *
 * @author Marcel Kolsteren
 */
public interface SamlIdpSession {
    /**
     * Returns the details of the principal, i.e. the logged in person
     *
     * @return the principal
     */
    SamlPrincipal getPrincipal();

    /**
     * Returns the list of service providers that participate in the session. The
     * list can be empty. In that case, the session is local to the identity
     * provider.
     *
     * @return the list
     */
    Set<SamlExternalServiceProvider> getServiceProviders();
}
