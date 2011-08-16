package org.jboss.seam.security.examples.id_provider;

import javax.enterprise.inject.Model;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;

@Model
public class Login {
    @Inject
    private SamlIdentityProviderApi samlIdentityProviderApi;

    private String userName;

    private String dialogueId;

    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private SamlIdentity identity;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getDialogueId() {
        return dialogueId;
    }

    public void setDialogueId(String dialogueId) {
        this.dialogueId = dialogueId;
    }

    public String login() {
        identity.localLogin(userName);
        if (dialogueId != null) {
            dialogueManager.attachDialogue(dialogueId);
            samlIdentityProviderApi.authenticationSucceeded((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
            dialogueManager.detachDialogue();
            return "SAML_LOGIN";
        } else {
            return "LOCAL_LOGIN";
        }
    }

    public void cancel() {
        if (dialogueId != null) {
            dialogueManager.attachDialogue(dialogueId);
            samlIdentityProviderApi.authenticationFailed((HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse());
            dialogueManager.detachDialogue();
        } else {
            throw new IllegalStateException("cancel method can only be called during a SAML login");
        }
    }
}
