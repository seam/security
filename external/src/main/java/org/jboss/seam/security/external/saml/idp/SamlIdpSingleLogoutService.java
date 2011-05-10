package org.jboss.seam.security.external.saml.idp;

import java.util.List;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.SamlNameIdImpl;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.saml.SamlConstants;
import org.jboss.seam.security.external.saml.SamlDialogue;
import org.jboss.seam.security.external.saml.SamlMessageFactory;
import org.jboss.seam.security.external.saml.SamlMessageSender;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlNameId;
import org.jboss.seam.security.external.saml.api.SamlPrincipal;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

/**
 * @author Marcel Kolsteren
 */
public class SamlIdpSingleLogoutService {
    @Inject
    private SamlMessageFactory samlMessageFactory;

    @Inject
    private SamlMessageSender samlMessageSender;

    @Inject
    private SamlIdpSessions samlIdpSessions;

    @Inject
    private Instance<SamlIdentityProviderSpi> samlIdentityProviderSpi;

    @Inject
    private Instance<DialogueBean> dialogue;

    @Inject
    private Instance<SamlDialogue> samlDialogue;

    @Inject
    private Instance<SamlIdpIncomingLogoutDialogue> samlIdpIncomingLogoutDialogue;

    @Inject
    private Instance<SamlIdpOutgoingLogoutDialogue> samlIdpOutgoingLogoutDialogue;

    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private ResponseHandler responseHandler;

    public void processSPRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, RequestAbstractType request) throws InvalidRequestException {
        if (!(request instanceof LogoutRequestType)) {
            throw new InvalidRequestException("Request should be a single logout request.");
        }

        LogoutRequestType logoutRequest = (LogoutRequestType) request;

        NameIDType nameIdJaxb = logoutRequest.getNameID();
        SamlNameId samlNameId = new SamlNameIdImpl(nameIdJaxb.getValue(), nameIdJaxb.getFormat(), nameIdJaxb.getNameQualifier());

        samlIdpIncomingLogoutDialogue.get().setNameId(samlNameId);
        samlIdpIncomingLogoutDialogue.get().setSessionIndexes(logoutRequest.getSessionIndex());

        removeNextSessionParticipant(httpResponse);
    }

    public void handleIDPInitiatedSingleLogout(SamlPrincipal principal, List<String> indexes, HttpServletResponse response) {
        samlIdpIncomingLogoutDialogue.get().setNameId(principal.getNameId());
        samlIdpIncomingLogoutDialogue.get().setSessionIndexes(indexes);

        removeNextSessionParticipant(response);
    }

    private void removeNextSessionParticipant(HttpServletResponse response) {
        SamlNameId samlNameId = samlIdpIncomingLogoutDialogue.get().getNameId();
        List<String> sessionIndexes = samlIdpIncomingLogoutDialogue.get().getSessionIndexes();

        boolean readyForNow = false;

        while (!readyForNow) {
            // Find the next session that matches with the removal criteria and
            // that has not been removed yet.
            SamlIdpSession sessionToRemove = null;
            for (SamlIdpSession session : samlIdpSessions.getSessions()) {
                if (session.getPrincipal().getNameId().equals(samlNameId)) {
                    if (sessionIndexes == null || sessionIndexes.size() == 0 || sessionIndexes.contains(((SamlIdpSessionImpl) session).getSessionIndex())) {
                        sessionToRemove = session;
                        break;
                    }
                }
            }

            if (sessionToRemove != null) {
                if (sessionToRemove.getServiceProviders().size() != 0) {
                    // For the session that is about to be removed, get the first
                    // service provider that participates in the session. Remove it
                    // from the session.
                    SamlExternalServiceProvider sp = sessionToRemove.getServiceProviders().iterator().next();
                    sessionToRemove.getServiceProviders().remove(sp);

                    // If the session participant is not the party that initiated the
                    // single logout, and it has a single logout service, send a
                    // single logout request. Otherwise, move on to the next session
                    // participant (if available) or to the next session.
                    if (sp != null && !sp.equals(samlDialogue.get().getExternalProvider()) && sp.getService(SamlProfile.SINGLE_LOGOUT) != null) {
                        String incomingDialogueId = dialogue.get().getId();
                        dialogueManager.detachDialogue();
                        dialogueManager.beginDialogue();
                        samlIdpOutgoingLogoutDialogue.get().setIncomingDialogueId(incomingDialogueId);

                        sendSingleLogoutRequestToSP(sessionToRemove, sp, response);
                        readyForNow = true;
                    }
                } else {
                    // Session has no participating service providers (any more).
                    // Remove the session.
                    samlIdpSessions.removeSession((SamlIdpSessionImpl) sessionToRemove);
                    if (samlDialogue.get().getExternalProvider() != null) {
                        samlIdentityProviderSpi.get().loggedOut(sessionToRemove);
                    }
                }
            } else {
                finishSingleLogoutProcess(response);
                readyForNow = true;
            }
        }
    }

    private void finishSingleLogoutProcess(HttpServletResponse response) {
        boolean failed = samlIdpIncomingLogoutDialogue.get().isFailed();
        if (samlDialogue.get().getExternalProvider() != null) {
            StatusResponseType statusResponse = samlMessageFactory.createStatusResponse(failed ? SamlConstants.STATUS_RESPONDER : SamlConstants.STATUS_SUCCESS, null);
            samlMessageSender.sendResponse(samlDialogue.get().getExternalProvider(), statusResponse, SamlProfile.SINGLE_LOGOUT, response);
        } else {
            if (failed) {
                samlIdentityProviderSpi.get().globalLogoutFailed(responseHandler.createResponseHolder(response));
            } else {
                samlIdentityProviderSpi.get().globalLogoutSucceeded(responseHandler.createResponseHolder(response));
            }
        }
        dialogue.get().setFinished(true);
    }

    public void processSPResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse, StatusResponseType statusResponse) {
        // End the outgoing samlDialogue and re-attach to the incoming
        // samlDialogue
        String incomingDialogueId = samlIdpOutgoingLogoutDialogue.get().getIncomingDialogueId();
        dialogueManager.endDialogue();
        dialogueManager.attachDialogue(incomingDialogueId);

        if (statusResponse.getStatus() != null && !statusResponse.getStatus().getStatusCode().getValue().equals(SamlConstants.STATUS_SUCCESS)) {
            samlIdpIncomingLogoutDialogue.get().setFailed(true);
        }

        removeNextSessionParticipant(httpResponse);
    }

    public void sendSingleLogoutRequestToSP(SamlIdpSession session, SamlExternalServiceProvider sp, HttpServletResponse response) {
        LogoutRequestType logoutRequest;
        logoutRequest = samlMessageFactory.createLogoutRequest(session.getPrincipal().getNameId(), ((SamlIdpSessionImpl) session).getSessionIndex());
        samlDialogue.get().setExternalProvider(sp);

        samlMessageSender.sendRequest(sp, SamlProfile.SINGLE_LOGOUT, logoutRequest, response);
    }
}
