package org.jboss.seam.security.external.spi;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * Interface that needs to be implemented by applications that want to act as a
 * SAML service provider. It is the counterpart of the
 * {@link SamlServiceProviderApi}.
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
public interface SamlServiceProviderSpi {
    /**
     * This method is called after successful external authentication of the
     * user. The session contains the details about the user. The call takes
     * place in the same dialogue context as the corresponding API call:
     * {@link SamlServiceProviderApi#login}. The dialogue can be used, for
     * example, to store the page that the user requested, so that the user can
     * be redirected to this page after login took place.
     *
     * @param session        session
     * @param responseHolder object holding the HTTP servlet response
     */
    void loginSucceeded(SamlSpSession session, ResponseHolder responseHolder);

    /**
     * This method is called after failed external authentication of the user.
     * The call takes place in the same dialogue context as the corresponding API
     * call.
     *
     * @param statusCodeLevel1 string indicating the top-level reason why the
     *                         logout failed (see SAMLv2 core specification, section 3.2.2.2:
     *                         top-level status code); it's required (never null)
     * @param statusCodeLevel2 string indicating the second-level reason why the
     *                         logout failed (see SAMLv2 core specification, section 3.2.2.2:
     *                         second-level status code); it's optional (can be null)
     * @param responseHolder   object holding the HTTP servlet response
     */
    void loginFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder);

    /**
     * When the service provider receives an unsolicited login from an identity
     * provider, this method is called.
     *
     * @param session        that has been created for this login
     * @param url            URL where the user needs to be redirected to; this URL is
     *                       supplied by the identity provider and can be null
     * @param responseHolder object holding the HTTP servlet response
     */
    void loggedIn(SamlSpSession session, String url, ResponseHolder responseHolder);

    /**
     * This method is the asynchronous callbacks related to
     * {@link SamlServiceProviderApi#globalLogout}. It is called when the single
     * logout was successful. Before this callback is called, the dialogue that
     * was active at the time of the API call is restored. An implementation of
     * this method will typically redirect the user to a page where a message is
     * shown that the user has been logged out.
     *
     * @param responseHolder object holding the HTTP servlet response
     */
    void globalLogoutSucceeded(ResponseHolder responseHolder);

    /**
     * <p>
     * This method is one of the asynchronous callbacks related to
     * {@link SamlServiceProviderApi#globalLogout}. It is called when the single
     * logout was unsuccessful. Before this callback is called, the dialogue that
     * was active at the time of the API call is restored. An implementation of
     * this method will typically redirect the user to a page where a message is
     * shown that the user could not be logged out.
     * </p>
     * <p/>
     * <p>
     * The fact that the single logout failed doesn't mean that all parts of the
     * single logout failed. Possibly only one of the session participants
     * couldn't perform a successful logout, while the others could.
     * </p>
     *
     * @param statusCodeLevel1 string indicating the top-level reason why the
     *                         logout failed (see SAMLv2 core specification, section 3.2.2.2:
     *                         top-level status code); it's required (never null)
     * @param statusCodeLevel2 string indicating the second-level reason why the
     *                         logout failed (see SAMLv2 core specification, section 3.2.2.2:
     *                         second-level status code); it's optional (can be null)
     * @param responseHolder   object holding the HTTP servlet response
     */
    void globalLogoutFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder);

    /**
     * When the service provider receives a logout request from an identity
     * provider, this method is called. The implementation of this method must
     * take for granted that the user has been logged out.
     *
     * @param session that has been removed
     */
    void loggedOut(SamlSpSession session);
}
