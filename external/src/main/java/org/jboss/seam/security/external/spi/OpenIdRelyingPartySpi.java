package org.jboss.seam.security.external.spi;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;

/**
 * Interface that needs to be implemented by applications that want to act as an
 * OpenID Relying Party. It is the counterpart of the
 * {@link OpenIdRelyingPartyApi}.
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
public interface OpenIdRelyingPartySpi {
    /**
     * This method is called after successful external authentication of the
     * user. The principal contains the details about the user. The call takes
     * place in the same dialogue context as the corresponding API call:
     * {@link OpenIdRelyingPartyApi#login}. The dialogue can be used, for
     * example, to store the page that the user requested, so that the user can
     * be redirected to this page after login took place.
     *
     * @param principal      principal
     * @param responseHolder object holding the HTTP servlet response
     */
    void loginSucceeded(OpenIdPrincipal principal, ResponseHolder responseHolder);

    /**
     * This method is called after failed external authentication of the user.
     * The call takes place in the same dialogue context as the corresponding API
     * call: {@link OpenIdRelyingPartyApi#login}.
     *
     * @param message        reason why the login failed
     * @param responseHolder object holding the HTTP servlet response
     */
    void loginFailed(String message, ResponseHolder responseHolder);
}
