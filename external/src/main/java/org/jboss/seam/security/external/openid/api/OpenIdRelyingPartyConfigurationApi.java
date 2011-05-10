package org.jboss.seam.security.external.openid.api;

import org.jboss.seam.security.external.api.EntityConfigurationApi;

/**
 * API for accessing the OpenID Relying Party configuration
 *
 * @author Marcel Kolsteren
 */
public interface OpenIdRelyingPartyConfigurationApi extends EntityConfigurationApi {
    /**
     * Gets the URL where the XRDS is served that can be used by OpenID providers
     * for relying party discovery. The XRDS document served at this URL is
     * described in the OpenID 2.0 Authentication specification, section 13.
     * Remark that some OpenID providers (e.g. Yahoo) require that a Yadis
     * discovery on the realm also results in this document. Meeting this
     * requirement is beyond the responsibility and beyond the reach of the Seam
     * OpenID module, because the realm URL is not "handled" by the web
     * application in which the OpenID module lives. Consult the Seam Security
     * documentation for further details about setting up the realm-based
     * discovery.
     *
     * @return the URL
     */
    String getXrdsURL();

    /**
     * Gets the realm that is used by the relying party. A "realm" is a pattern
     * that represents the part of URL-space for which an OpenID Authentication
     * request is valid. See OpenID 2.0 Authentication specification, section
     * 9.2. The OpenID provider uses the realm as the name of the the relying
     * party site that is presented to the end user.
     *
     * @return the realm
     */
    String getRealm();
}
