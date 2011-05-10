package org.jboss.seam.security.external.saml.idp;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;

/**
 * @author Marcel Kolsteren
 */
@DialogueScoped
public class SamlIdpOutgoingLogoutDialogue {
    private SamlIdpSession session;

    private String incomingDialogueId;

    public SamlIdpSession getSession() {
        return session;
    }

    public void setSession(SamlIdpSession session) {
        this.session = session;
    }

    public String getIncomingDialogueId() {
        return incomingDialogueId;
    }

    public void setIncomingDialogueId(String incomingDialogueId) {
        this.incomingDialogueId = incomingDialogueId;
    }

}
