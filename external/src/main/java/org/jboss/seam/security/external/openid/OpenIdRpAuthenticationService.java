package org.jboss.seam.security.external.openid;

import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.OpenIdPrincipalImpl;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;

/**
 * @author Marcel Kolsteren
 */
public
@ApplicationScoped
class OpenIdRpAuthenticationService {
    
    @Inject
    private OpenIdRequest openIdRequest;

    @Inject
    private ConsumerManager openIdConsumerManager;

    @Inject
    private Instance<OpenIdRelyingPartySpi> openIdRelyingPartySpi;

    @Inject
    private Instance<OpenIdRpBeanApi> relyingPartyBean;

    @Inject
    private ResponseHandler responseHandler;

    @Inject
    private Logger log;
    
    @Inject HttpSession session;

    @Inject
    private Instance<DialogueBean> dialogue;

    public void handleIncomingMessage(HttpServletRequest httpRequest,
                                      HttpServletResponse httpResponse) throws InvalidRequestException {
        processIncomingMessage(new ParameterList(httpRequest.getParameterMap()), httpRequest.getQueryString(), httpResponse);
    }    

    public void processIncomingMessage(ParameterList parameterList, String queryString, HttpServletResponse httpResponse) {
        try {
            // retrieve the previously stored discovery information
            DiscoveryInformation discovered = openIdRequest.getDiscoveryInformation();
            if (discovered == null) {
                throw new IllegalStateException("No discovery information found in OpenID request");
            }

            // extract the receiving URL from the HTTP request            
            StringBuffer receivingURL = new StringBuffer(relyingPartyBean.get().getServiceURL(OpenIdService.OPEN_ID_SERVICE));
            
            if (queryString != null && queryString.length() > 0)
                receivingURL.append("?").append(queryString);

            // verify the response; ConsumerManager needs to be the same
            // (static) instance used to place the authentication request
            VerificationResult verification = openIdConsumerManager.verify(
                    receivingURL.toString(), parameterList, discovered);

            // examine the verification result and extract the verified identifier
            Identifier identifier = verification.getVerifiedId();

            if (identifier != null) {
                AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();

                Map<String, List<String>> attributeValues = null;
                if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
                    FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);
                    @SuppressWarnings("unchecked")
                    Map<String, List<String>> attrValues = fetchResp.getAttributes();
                    attributeValues = attrValues;
                }

                OpenIdPrincipal principal = createPrincipal(identifier.getIdentifier(),
                        discovered.getOPEndpoint(), attributeValues);

                openIdRelyingPartySpi.get().loginSucceeded(principal,
                        responseHandler.createResponseHolder(httpResponse));
            } else {
                openIdRelyingPartySpi.get().loginFailed(verification.getStatusMsg(),
                        responseHandler.createResponseHolder(httpResponse));
            }
        } catch (OpenIDException e) {
            responseHandler.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage(), httpResponse);
            return;
        }

        dialogue.get().setFinished(true);
    }
    
    @Dialogued(join = true)
    public void sendAuthRequest(String openId, List<OpenIdRequestedAttribute> attributes,
                                HttpServletResponse response) {
        try {
            @SuppressWarnings("unchecked")
            List<DiscoveryInformation> discoveries = openIdConsumerManager.discover(openId);

            DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);

            openIdRequest.setDiscoveryInformation(discovered);

            String realm = relyingPartyBean.get().getRealm();
            String returnTo = relyingPartyBean.get().getServiceURL(
                    OpenIdService.OPEN_ID_SERVICE) + "?dialogueId=" + dialogue.get().getId();
            AuthRequest authReq = openIdConsumerManager.authenticate(discovered, returnTo, realm);

            if (attributes != null && attributes.size() > 0) {
                FetchRequest fetch = FetchRequest.createFetchRequest();
                for (OpenIdRequestedAttribute attribute : attributes) {
                    fetch.addAttribute(attribute.getAlias(), attribute.getTypeUri(), attribute.isRequired());
                }
                // attach the extension to the authentication request
                authReq.addExtension(fetch);
            }

            String url = authReq.getDestinationUrl(true);

            responseHandler.sendHttpRedirectToUserAgent(url, response);
        } catch (OpenIDException e) {
            log.warn("Authentication failed", e);
            openIdRelyingPartySpi.get().loginFailed(e.getMessage(),
                    responseHandler.createResponseHolder(response));
        }
    }

    private OpenIdPrincipal createPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributeValues) {
        return new OpenIdPrincipalImpl(identifier, openIdProvider, attributeValues);
    }
}
