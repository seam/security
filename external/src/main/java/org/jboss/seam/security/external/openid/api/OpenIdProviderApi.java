package org.jboss.seam.security.external.openid.api;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.openid.OpenIdProviderInApplicationScopeProducer;
import org.jboss.seam.security.external.openid.OpenIdProviderInVirtualApplicationScopeProducer;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * API to the OpenID Provider (OP) of Seam security. In order to use this API,
 * one of the following alternative beans needs to be activated:
 * <p/>
 * <ul>
 * <li>{@link OpenIdProviderInApplicationScopeProducer}</li>
 * <li>{@link OpenIdProviderInVirtualApplicationScopeProducer}</li>
 * </ul>
 * <p/>
 * The former will install the OpenID provider in application scope, the latter
 * will install it in virtual application scope. The virtual application scope
 * allows for using different provider configurations depending on the server
 * name. See {@link VirtualApplicationScoped}.
 * <p/>
 * <p>
 * This API (implemented by the framework) comes along with an SPI:
 * {@link OpenIdProviderSpi} (implemented by the client application). Dialogues
 * are used to bridge corresponding API and SPI calls (see {@link Dialogued}).
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
public interface OpenIdProviderApi {
    /**
     * This is one of the possible reactions of the application after having
     * received and processed an authentication request through the API call
     * {@link OpenIdProviderSpi#authenticate(String, String, boolean, ResponseHolder)}
     * . By calling this method, the application informs the OpenID provider
     * module that authentication succeeded. The userName of the authenticated
     * user is provided. The OpenID provider module will redirect the user back
     * to the relying party's website.
     *
     * @param userName user name
     * @param response HTTP response
     */
    void authenticationSucceeded(String userName, HttpServletResponse response);

    /**
     * This is one of the possible reactions of the application after having
     * received and processed an authentication request through the API call
     * {@link OpenIdProviderSpi#authenticate(String, String, boolean, ResponseHolder)}
     * . By calling this method, the application informs the OpenID provider
     * module that authentication failed. The OpenID provider module will
     * redirect the user back to the relying party's website.
     *
     * @param userName user name
     * @param response HTTP response
     */
    void authenticationFailed(HttpServletResponse response);

    void setAttributes(Map<String, List<String>> attributeValues, HttpServletResponse response);

    /**
     * This method can be used to find out the OP-Local identifier for a given
     * user name. The OpenID authentication specification defines this identifier
     * as follows: 'An alternate Identifier for an end user that is local to a
     * particular OP and thus not necessarily under the end user's control'.
     *
     * @param userName user name
     * @return the OP-Local Identifier
     */
    String getOpLocalIdentifierForUserName(String userName);
}
