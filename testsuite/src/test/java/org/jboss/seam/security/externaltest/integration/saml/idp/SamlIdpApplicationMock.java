package org.jboss.seam.security.externaltest.integration.saml.idp;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.SamlMultiUserIdentityProviderApi;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

@ApplicationScoped
public class SamlIdpApplicationMock implements SamlIdentityProviderSpi {
    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private Dialogue dialogue;

    @Inject
    private Instance<SamlMultiUserIdentityProviderApi> idpApi;

    private String dialogueId;

    @Inject
    private Logger log;

    public void authenticate(ResponseHolder responseHolder) {
        dialogueId = dialogue.getId();
        try {
            responseHolder.getResponse().getWriter().print("Please login");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void handleLogin(String userName, HttpServletResponse response) {
        SamlIdpSession session = idpApi.get().localLogin(idpApi.get().createNameId(userName, null, null), null);
        dialogueManager.attachDialogue(dialogueId);
        idpApi.get().authenticationSucceeded(session, response);
        dialogueManager.detachDialogue();
    }

    public int getNumberOfSessions() {
        return idpApi.get().getSessions().size();
    }

    public void globalLogoutFailed(ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().getWriter().print("Single logout failed");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void globalLogoutSucceeded(ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().getWriter().print("Single logout succeeded");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Dialogued
    public void handleSingleLogout(HttpServletResponse response) {
        idpApi.get().globalLogout(idpApi.get().getSessions().iterator().next(), response);
    }

    public void loggedOut(SamlIdpSession session) {
        log.info("User " + session.getPrincipal().getNameId().getValue() + " has been logged out.");
    }
}
