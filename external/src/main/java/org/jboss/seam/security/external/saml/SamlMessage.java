package org.jboss.seam.security.external.saml;

/**
 * @author Marcel Kolsteren
 */
public class SamlMessage {
    public static final String QSP_SAML_REQUEST = "SAMLRequest";
    public static final String QSP_SAML_RESPONSE = "SAMLResponse";
    public static final String QSP_RELAY_STATE = "RelayState";

    protected SamlRequestOrResponse samlRequestOrResponse;

    protected String samlMessage;

    protected String relayState;

    public SamlRequestOrResponse getRequestOrResponse() {
        return samlRequestOrResponse;
    }

    public void setRequestOrResponse(SamlRequestOrResponse samlRequestOrResponse) {
        this.samlRequestOrResponse = samlRequestOrResponse;
    }

    public String getSamlMessage() {
        return samlMessage;
    }

    public void setSamlMessage(String samlMessage) {
        this.samlMessage = samlMessage;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }
}
