package org.jboss.seam.security.external.openid.api;

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Object respresenting a person that has been authenticated using OpenID.
 *
 * @author Marcel Kolsteren
 */
public interface OpenIdPrincipal {
    /**
     * This identifier holds the OpenID that is owned by the person.
     *
     * @return the verified OpenID
     */
    String getIdentifier();

    /**
     * The endpoint URL of the authentication service of the OpenID provider that
     * verified that the person owns the OpenID.
     *
     * @return the OpenID provider authentication endpoint URL
     */
    URL getOpenIdProvider();

    /**
     * The attributes of the person, that have been received from the OpenID
     * provider. It maps aliases of requested attributes to lists of attribute
     * values.
     *
     * @return the attribute map
     */
    Map<String, List<String>> getAttributeValues();

    /**
     * Convenience method for fetching the first value of the attribute with the
     * given alias. If the attribute doesn't exits, it returns null;
     *
     * @param alias attribute alias
     * @return the first value of the attribute, or null
     */
    String getAttribute(String alias);
}
