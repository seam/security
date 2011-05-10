package org.jboss.seam.security.external.saml;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.servlet.ServletRequest;

/**
 * @author Marcel Kolsteren
 */
public class SamlRedirectMessage extends SamlMessage {
    // Query string parameters used by the HTTP_Redirect binding
    public static final String QSP_SIGNATURE = "Signature";
    public static final String QSP_SIG_ALG = "SigAlg";

    private String signature;

    private String signatureAlgorithm;

    // If this is true, the samlMessage, signature, signatureAlgorithm and
    // relayState values are in url encoded form
    private boolean urlEncoded;

    public SamlRedirectMessage() {
    }

    public SamlRedirectMessage(SamlRequestOrResponse samlRequestOrResponse, ServletRequest request) {
        this.samlRequestOrResponse = samlRequestOrResponse;
        if (samlRequestOrResponse.isRequest()) {
            samlMessage = request.getParameter(SamlRedirectMessage.QSP_SAML_REQUEST);
        } else {
            samlMessage = request.getParameter(SamlRedirectMessage.QSP_SAML_RESPONSE);
        }
        relayState = request.getParameter(SamlRedirectMessage.QSP_RELAY_STATE);
        signatureAlgorithm = request.getParameter(SamlRedirectMessage.QSP_SIG_ALG);
        signature = request.getParameter(SamlRedirectMessage.QSP_SIGNATURE);
        urlEncoded = true;
    }

    public String createQueryString() {
        if (!urlEncoded) {
            encode();
        }
        StringBuilder queryString = new StringBuilder();
        if (samlRequestOrResponse.isRequest()) {
            addParamToQueryString(queryString, SamlRedirectMessage.QSP_SAML_REQUEST, samlMessage);
        } else {
            addParamToQueryString(queryString, SamlRedirectMessage.QSP_SAML_RESPONSE, samlMessage);
        }
        addParamToQueryString(queryString, SamlMessage.QSP_RELAY_STATE, relayState);
        addParamToQueryString(queryString, SamlRedirectMessage.QSP_SIG_ALG, signatureAlgorithm);
        addParamToQueryString(queryString, SamlRedirectMessage.QSP_SIGNATURE, signature);

        return queryString.toString();
    }

    private void addParamToQueryString(StringBuilder queryString, String parameterName, String parameterValue) {
        if (parameterValue != null && parameterValue.length() != 0) {
            if (queryString.length() != 0) {
                queryString.append('&');
            }
            queryString.append(parameterName);
            queryString.append('=');
            queryString.append(parameterValue);
        }
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean isUrlEncoded() {
        return urlEncoded;
    }

    public void setUrlEncoded(boolean urlEncoded) {
        this.urlEncoded = urlEncoded;
    }

    public void encode() {
        if (!urlEncoded) {
            samlMessage = urlEncode(samlMessage);
            signature = urlEncode(signature);
            signatureAlgorithm = urlEncode(signatureAlgorithm);
            relayState = urlEncode(relayState);
            urlEncoded = true;
        }
    }

    public void decode() {
        if (urlEncoded) {
            samlMessage = urlDecode(samlMessage);
            signature = urlDecode(signature);
            signatureAlgorithm = urlDecode(signatureAlgorithm);
            relayState = urlDecode(relayState);
            urlEncoded = false;
        }
    }

    private String urlEncode(String value) {
        if (value == null) {
            return null;
        }
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private String urlDecode(String value) {
        if (value == null) {
            return null;
        }
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
