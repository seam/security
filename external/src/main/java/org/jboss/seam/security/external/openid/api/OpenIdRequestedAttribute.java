package org.jboss.seam.security.external.openid.api;

/**
 * Attribute requested by the relying party during the authentication of a user.
 *
 * @author Marcel Kolsteren
 */
public interface OpenIdRequestedAttribute {
    /**
     * Name that identifies this requested attribute.
     *
     * @return the alias
     */
    String getAlias();

    /**
     * Attribute type identifier.
     *
     * @return the type URI
     */
    String getTypeUri();

    /**
     * Indicates whether the attribute is required.
     *
     * @return true if required, false otherwise
     */
    boolean isRequired();

    /**
     * Indicates the maximum number of values to be returned by the provider;
     * must be at least 1.
     *
     * @return maximum number of values
     */
    Integer getCount();
}
