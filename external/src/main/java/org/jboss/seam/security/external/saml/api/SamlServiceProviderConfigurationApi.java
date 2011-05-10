package org.jboss.seam.security.external.saml.api;

import java.util.List;

import org.jboss.seam.security.external.saml.sp.SamlExternalIdentityProvider;

/**
 * API for the configuration of a SAML Service Provider.
 *
 * @author Marcel Kolsteren
 */
public interface SamlServiceProviderConfigurationApi extends SamlEntityConfigurationApi {
    /**
     * If this property is enabled, all authentication requests targeted at
     * identity providers will be signed. The property is disabled by default.
     * When enabling it, be sure to add a signing key by calling
     * {@link SamlEntityConfigurationApi#setSigningKey(String, String, String, String)}
     * .
     *
     * @return true iff the authentication requests are signed
     */
    boolean isAuthnRequestsSigned();

    /**
     * See {@link #isAuthnRequestsSigned}.
     */
    void setAuthnRequestsSigned(boolean authnRequestsSigned);

    /**
     * This property, which is enabled by default, determines whether incoming
     * authentication responses from the identity provider are required to have a
     * valid signature. It is strongly discouraged to disabled signature
     * validation, because this opens possibilities for sending fake
     * authentication responses to the service provider.
     *
     * @return true iff incoming assertions need to have a valid signature
     */
    boolean isWantAssertionsSigned();

    /**
     * See {@link #isWantAssertionsSigned()}.
     */
    void setWantAssertionsSigned(boolean wantAssertionsSigned);

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
     * Returns a list with all identity providers that are trusted (i.e. identity
     * providers that have been added by calling
     * {@link SamlEntityConfigurationApi#addExternalSamlEntity}). This allows the
     * API client to present the list to the user, so that the user can choose
     * the provider that needs to be used for doing the login.
     *
     * @return list of identity providers
     */
    List<SamlExternalIdentityProvider> getIdentityProviders();
}
