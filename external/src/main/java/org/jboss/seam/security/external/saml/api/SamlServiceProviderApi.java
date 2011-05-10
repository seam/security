package org.jboss.seam.security.external.saml.api;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.SamlSingleUserServiceProviderSpi;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.sp.SamlSpInApplicationScopeProducer;
import org.jboss.seam.security.external.saml.sp.SamlSpInVirtualApplicationScopeProducer;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * API to the SAMLv2 compliant service provider. In order to use this API, one
 * of the following alternative beans needs to be activated:
 * <p/>
 * <ul>
 * <li>{@link SamlSpInApplicationScopeProducer}</li>
 * <li>{@link SamlSpInVirtualApplicationScopeProducer}</li>
 * </ul>
 * <p/>
 * The former will install the service provider in application scope, the latter
 * will install it in virtual application scope. The virtual application scope
 * allows for using different service provider configurations depending on the
 * server name. See {@link VirtualApplicationScoped}.
 * <p/>
 * <p>
 * This API (implemented by the framework) comes along with an SPI:
 * {@link SamlServiceProviderSpi} (implemented by the client application).
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
public interface SamlServiceProviderApi {
    /**
     * Sends the user agent to the site of the given identity provider, where the
     * user can be authenticated. When the call returns, a redirect on the HTTP
     * response has taken place. The response of the identity provider will be
     * sent asynchronously through the SPI methods
     * {@link SamlSingleUserServiceProviderSpi#loginSucceeded(OpenIdSession)} or
     * {@link SamlSingleUserServiceProviderSpi#loginFailed(OpenIdSession)}. If
     * the method is called within a dialogue, that same dialogue will be active
     * when the SPI method is called. Thus, the dialogue can be used to store API
     * client state that needs to survive the sign on process.
     *
     * @param idpEntityId
     * @param response    the HTTP servlet response
     */
    public void login(String idpEntityId, HttpServletResponse response);

    /**
     * <p>
     * Locally logs out the user. This use case is considered out of scope by the
     * SAML spec (see the SAMLv2 Profiles document, section 4.4). The local
     * logout means that the session established by the SAML SP is not used any
     * more by the application. So when the SAML SP will receive a logout request
     * for this session in the future, it won't pass that on to the application.
     * </p>
     * <p/>
     * <p>
     * This method doesn't write the HTTP response.
     * </p>
     */
    public void localLogout();

    /**
     * Globally logs out the user. The browser of the user is redirected to the
     * site of the identity provider, so that the identity provider can logout
     * the user from all applications that share the same session at the identity
     * provider. The result of the logout operation is reported back
     * asynchronously through the SPI methods
     * {@link SamlSingleUserServiceProviderSpi#globalLogoutSucceeded()} and
     * {@link SamlSingleUserServiceProviderSpi#singleLogoutFailed()}. If this
     * method is called with an active dialogue scope, the same dialogue will be
     * active when the SPI method is called. This allows the API client to store
     * state information in the dialogue.
     *
     * @param response the HTTP servlet response
     */
    public void globalLogout(HttpServletResponse response);

    /**
     * Gets the current session (login). If there is no active session, null is
     * returned.
     *
     * @return active session, or null
     */
    public SamlSpSession getSession();
}
