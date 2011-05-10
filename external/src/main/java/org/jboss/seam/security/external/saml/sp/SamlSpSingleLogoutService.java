package org.jboss.seam.security.external.saml.sp;

import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.SamlNameIdImpl;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlMessageFactory;
import org.jboss.seam.security.external.saml.SamlMessageSender;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.api.SamlNameId;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;

/**
 * @author Marcel Kolsteren
 */
public class SamlSpSingleLogoutService {
    @Inject
    private SamlMessageFactory samlMessageFactory;

    @Inject
    private SamlMessageSender samlMessageSender;

    @Inject
    private SamlSpSessions samlSpSessions;

    @Inject
    private Instance<SamlServiceProviderSpi> samlServiceProviderSpi;

    @Inject
    private SamlSpLogoutDialogue samlSpLogoutDialogue;

    @Inject
    private DialogueBean dialogue;

    @Inject
    private SamlDialogue samlDialogue;

    @Inject
    private ResponseHandler responseHandler;

    public void processIDPRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, RequestAbstractType request) throws InvalidRequestException {
        if (!(request instanceof LogoutRequestType)) {
            throw new InvalidRequestException("Request should be a single logout request.");
        }

        LogoutRequestType logoutRequest = (LogoutRequestType) request;
        SamlExternalIdentityProvider idp = (SamlExternalIdentityProvider) samlDialogue.getExternalProvider();

        NameIDType nameIdJaxb = logoutRequest.getNameID();
        SamlNameId samlNameId = new SamlNameIdImpl(nameIdJaxb.getValue(), nameIdJaxb.getFormat(), nameIdJaxb.getNameQualifier());
        removeSessions(samlNameId, idp.getEntityId(), logoutRequest.getSessionIndex());

        StatusResponseType statusResponse = samlMessageFactory.createStatusResponse(SamlConstants.STATUS_SUCCESS, null);

        samlMessageSender.sendResponse(idp, statusResponse, SamlProfile.SINGLE_LOGOUT, httpResponse);

        dialogue.setFinished(true);
    }

    private void removeSessions(SamlNameId nameId, String idpEntityId, List<String> sessionIndexes) {
        for (SamlSpSessionImpl session : samlSpSessions.getSessions()) {
            if (session.getPrincipal().getNameId().equals(nameId) && session.getIdentityProvider().getEntityId().equals(idpEntityId)) {
                if (sessionIndexes.size() == 0 || sessionIndexes.contains(session.getSessionIndex())) {
                    samlSpSessions.removeSession((SamlSpSessionImpl) session);
                    samlServiceProviderSpi.get().loggedOut(session);
                }
            }
        }
    }

    public void processIDPResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse, StatusResponseType statusResponse) {
        StatusType status = statusResponse.getStatus();
        if (status.getStatusCode().getValue().equals(SamlConstants.STATUS_SUCCESS)) {
            samlServiceProviderSpi.get().globalLogoutSucceeded(responseHandler.createResponseHolder(httpResponse));
        } else {
            String statusCodeLevel1 = status.getStatusCode().getValue();
            String statusCodeLevel2 = null;
            if (status.getStatusCode().getStatusCode() != null) {
                statusCodeLevel2 = status.getStatusCode().getStatusCode().getValue();
            }
            samlServiceProviderSpi.get().globalLogoutFailed(statusCodeLevel1, statusCodeLevel2, responseHandler.createResponseHolder(httpResponse));
        }
        dialogue.setFinished(true);
    }

    public void sendSingleLogoutRequestToIDP(SamlSpSessionImpl session, HttpServletResponse httpResponse) {
        SamlExternalIdentityProvider idp = session.getIdentityProvider();
        LogoutRequestType logoutRequest;
        logoutRequest = samlMessageFactory.createLogoutRequest(session.getPrincipal().getNameId(), session.getSessionIndex());

        samlDialogue.setExternalProvider(idp);
        samlSpLogoutDialogue.setSession(session);

        samlMessageSender.sendRequest(idp, SamlProfile.SINGLE_LOGOUT, logoutRequest, httpResponse);
    }
}
