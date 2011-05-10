package org.jboss.seam.security.external.saml.sp;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;
import org.jboss.seam.security.external.saml.api.SamlSpSession;

/**
 * @author Marcel Kolsteren
 */
@DialogueScoped
public class SamlSpLogoutDialogue {
    private SamlSpSession session;

    public SamlSpSession getSession() {
        return session;
    }

    public void setSession(SamlSpSession session) {
        this.session = session;
    }

}
