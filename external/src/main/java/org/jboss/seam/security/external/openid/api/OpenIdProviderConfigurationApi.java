package org.jboss.seam.security.external.openid.api;

import org.jboss.seam.security.external.api.EntityConfigurationApi;

/**
 * API for accessing the OpenID Provider configuration
 *
 * @author Marcel Kolsteren
 */
public interface OpenIdProviderConfigurationApi extends EntityConfigurationApi {
    /**
     * Gets the URL where the XRDS is served that can be used by relying parties
     * for OpenID Provider discovery. The document served at this URL is
     * described in the OpenID 2.0 Authentication specification, section
     * 7.3.2.1.1.
     *
     * @return the URL
     */
    String getXrdsURL();
}
