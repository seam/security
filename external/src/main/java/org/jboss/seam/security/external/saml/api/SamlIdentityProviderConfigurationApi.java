package org.jboss.seam.security.external.saml.api;

import java.util.List;

import org.jboss.seam.security.external.saml.idp.SamlExternalServiceProvider;

/**
 * API for the configuration of a SAML Identity Provider
 *
 * @author Marcel Kolsteren
 */
public interface SamlIdentityProviderConfigurationApi extends SamlEntityConfigurationApi {
    /**
     * This property indicates whether incoming authentication requests need to
     * be signed. This property is disabled (false) by default.
     *
     * @return true iff the authentication requests need to be signed
     */
    boolean isWantAuthnRequestsSigned();

    /**
     * See {@link #isWantAuthnRequestsSigned()}.
     */
    void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned);

    /**
     * This property indicates whether outgoing single logout messages are
     * signed. True by default, and the advice is not to disable this property,
     * unless you understand the security risks of doing so.
     *
     * @return true iff the single logout requests (sent to identity providers)
     *         are signed
     */
    boolean isSingleLogoutMessagesSigned();

    /**
     * See {@link #isSingleLogoutMessagesSigned()}.
     */
    void setSingleLogoutMessagesSigned(boolean singleLogoutMessagesSigned);

    /**
     * This property indicates whether incoming single logout requests are
     * required to have a valid signature. True by default, and the advice is not
     * to disable this property, unless you understand the security risks of
     * doing so.
     *
     * @return true iff incoming single logout requests need to have a valid
     *         signature
     */
    boolean isWantSingleLogoutMessagesSigned();

    /**
     * See {@link #isWantSingleLogoutMessagesSigned()}.
     */
    void setWantSingleLogoutMessagesSigned(boolean wantSingleLogoutMessagesSigned);

    /**
     * Gets a list of all external service providers that have been added
     * previously by calling
     * {@link SamlEntityConfigurationApi#addExternalSamlEntity}.
     *
     * @return the list
     */
    List<SamlExternalServiceProvider> getServiceProviders();
}
