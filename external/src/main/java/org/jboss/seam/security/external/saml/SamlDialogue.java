package org.jboss.seam.security.external.saml;

import org.jboss.seam.security.external.dialogues.api.DialogueScoped;

/**
 * @author Marcel Kolsteren
 */
@DialogueScoped
public class SamlDialogue {
    private SamlExternalEntity externalProvider;

    private String externalProviderMessageId;

    private String externalProviderRelayState;

    public void setExternalProvider(SamlExternalEntity externalProvider) {
        this.externalProvider = externalProvider;
    }

    public SamlExternalEntity getExternalProvider() {
        return externalProvider;
    }

    public String getExternalProviderMessageId() {
        return externalProviderMessageId;
    }

    public void setExternalProviderMessageId(String externalProviderRequestId) {
        this.externalProviderMessageId = externalProviderRequestId;
    }

    public String getExternalProviderRelayState() {
        return externalProviderRelayState;
    }

    public void setExternalProviderRelayState(String externalProviderRelayState) {
        this.externalProviderRelayState = externalProviderRelayState;
    }

}
