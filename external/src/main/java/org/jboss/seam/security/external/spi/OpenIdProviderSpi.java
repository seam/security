package org.jboss.seam.security.external.spi;

import java.util.List;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Interface that needs to be implemented by applications that want to act as an
 * OpenID Provider. It is the counterpart of the {@link OpenIdProviderApi}.
 * <p/>
 * Most methods in this interface have a responseHolder parameter, which
 * contains the HTTP response. This is a way of handing over the control over
 * the browser to the application. The application is responsible for writing
 * the response (either a normal HTML response, or an error, or a redirect).
 * Typically, the application will redirect the user to a URL within the
 * application.
 *
 * @author Marcel Kolsteren
 */

public interface OpenIdProviderSpi {
    /**
     * This method is called after receipt of an authentication request from a
     * relying party. Upon receipt of this call, the application should try to
     * authenticate the user (either silently or interacting with the user). The
     * result of the authentication needs to be reported back using the API calls
     * {@link OpenIdProviderApi#authenticationSucceeded} or
     * {@link OpenIdProviderApi#authenticationFailed}.
     *
     * @param realm          represents the part of URL-space for which the authentication
     *                       is valid; realms are designed to give the end user an indication
     *                       of the scope of the authentication request; the application
     *                       should present the realm when requesting the end user's approval
     *                       for the authentication request
     * @param userName       this optional attribute indicates the end user that needs
     *                       to be authenticated; if this parameter is null, the application
     *                       needs to ask the use for her username
     * @param immediate      if this is true, there must be no interaction with the
     *                       user (silent authentication)
     * @param responseHolder
     */
    void authenticate(String realm, String userName, boolean immediate, ResponseHolder responseHolder);

    /**
     * This method is called to check whether a username exists.
     *
     * @param userName the username
     * @return true if a user with that username exists, false otherwise
     */
    boolean userExists(String userName);

    void fetchParameters(List<OpenIdRequestedAttribute> requestedAttributes, ResponseHolder responseHolder);
}
