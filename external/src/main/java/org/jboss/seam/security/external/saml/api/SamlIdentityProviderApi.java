package org.jboss.seam.security.external.saml.api;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AttributeType;
import org.jboss.seam.security.external.saml.idp.SamlIdpInApplicationScopeProducer;
import org.jboss.seam.security.external.saml.idp.SamlIdpInVirtualApplicationScopeProducer;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * API to the SAML Identity Provider (IDP) of Seam security. In order to use
 * this API, one of the following alternative beans needs to be activated:
 * <p/>
 * <ul>
 * <li>{@link SamlIdpInApplicationScopeProducer}</li>
 * <li>{@link SamlIdpInVirtualApplicationScopeProducer}</li>
 * </ul>
 * <p/>
 * The former will install the Identity Provider in application scope, the
 * latter will install it in virtual application scope. The virtual application
 * scope allows for using different provider configurations depending on the
 * server name. See {@link VirtualApplicationScoped}.
 * <p/>
 * <p>
 * This API (implemented by the framework) comes along with an SPI:
 * {@link SamlIdentityProviderSpi} (implemented by the client application).
 * Dialogues are used to bridge corresponding API and SPI calls (see
 * {@link Dialogued}).
 * </p>
 * <p/>
 * <p>
 * Most methods in this API require that the HTTP response is passed as a
 * parameter. The implementation needs the response, in order to redirect the
 * browser to the relying party. Beware not to touch the HTTP response after one
 * of these method returns.
 * </p>
 *
 * @author Marcel Kolsteren
 */

public interface SamlIdentityProviderApi {
    /**
     * Creates a local SAML session for the user with the given name and
     * attributes. This call is typically done before a {@link #remoteLogin} or
     * an {@link #authenticationSucceeded} call.
     *
     * @param nameId
     * @param attributes
     */
    void localLogin(SamlNameId nameId, List<AttributeType> attributes);

    /**
     * Creates a name identifier with the given properties. Needed for
     * constructing the nameId parameter of a {@link #localLogin} call.
     *
     * @param value     value (required)
     * @param format    format (optional)
     * @param qualifier qualifier (optional)
     * @return the name identifier
     */
    SamlNameId createNameId(String value, String format, String qualifier);

    /**
     * <p>
     * Logs the user in remotely in the application of the given service
     * provider. If the remote URL is specified, the service provider will
     * redirect the user to that URL within the service provider's application.
     * Otherwise, the service provider will determine for itself which page is
     * shown to the user.
     * </p>
     * <p/>
     * <p>
     * In SAML terms, this call results in an "unsolicited login" at the side of
     * the service provider.
     * </p>
     *
     * @param spEntityId the entity id of the remote service provider
     * @param remoteUrl  the URL where the user agent needs to be redirected to by
     *                   the service provider (can be null)
     * @param response   the HTTP servlet response
     */
    void remoteLogin(String spEntityId, String remoteUrl, HttpServletResponse response);

    /**
     * This is one of the possible responses that relate to the SPI call
     * {@link SamlIdentityProviderSpi#authenticate}. If should be called in the
     * same dialogue context as the corresponding SPI call. It instructs the SAML
     * identity provider to send a positive authentication result back to the
     * service provider, using the local SAML session, which must have been
     * established before this call is done (by a previous call to
     * {@link #localLogin}).
     *
     * @param response the HTTP servlet response
     */
    void authenticationSucceeded(HttpServletResponse response);

    /**
     * This is one of the possible responses that relate to the SPI call
     * {@link SamlIdentityProviderSpi#authenticate}. If should be called in the
     * same dialogue context as the corresponding SPI call. It instructs the SAML
     * identity provider to send a positive authentication result back to the
     * service provider.
     *
     * @param response the HTTP servlet response
     */
    void authenticationFailed(HttpServletResponse response);

    /**
     * Gets the current SAML session. This contains information about the logged
     * in user, and the external service providers that take part in this
     * session.
     *
     * @return the session
     */
    SamlIdpSession getSession();

    /**
     * Removes the local SAML session for the current user. This use case is
     * considered out of scope by the SAML spec (see the SAMLv2 Profiles
     * document, section 4.4). External service providers that take part in the
     * session are <b>not</b> informed about the fact that the shared session has
     * been removed at the identity provider side.
     */
    void localLogout();

    /**
     * Globally logs out the current user. This leads to a "single logout" where
     * the identity provider logs out the user from all service providers that
     * participate in the current session. The result of the global logout is
     * reported asynchronously through the SPI.
     *
     * @param response the HTTP servlet response
     */
    void globalLogout(HttpServletResponse response);

}
