package org.jboss.seam.security.external.saml.idp;

import java.util.List;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.seam.security.external.saml.api.SamlNameId;

/**
 * @author Marcel Kolsteren
 */
@DialogueScoped
public class SamlIdpIncomingLogoutDialogue {
    private SamlNameId nameId;

    private List<String> sessionIndexes;

    private boolean failed;

    public SamlNameId getNameId() {
        return nameId;
    }

    public void setNameId(SamlNameId nameId) {
        this.nameId = nameId;
    }

    public List<String> getSessionIndexes() {
        return sessionIndexes;
    }

    public void setSessionIndexes(List<String> sessionIndexes) {
        this.sessionIndexes = sessionIndexes;
    }

    public boolean isFailed() {
        return failed;
    }

    public void setFailed(boolean failure) {
        this.failed = failure;
    }

}
