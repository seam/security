package org.jboss.seam.security.external;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.DialogueFilter;

/**
 * @author Marcel Kolsteren
 */
public class ResponseHolderImpl implements ResponseHolder {
    private HttpServletResponse response;

    private String dialogueId;

    public ResponseHolderImpl(HttpServletResponse response, String dialogueId) {
        this.response = response;
        this.dialogueId = dialogueId;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }

    public void redirectWithDialoguePropagation(String url) {
        if (dialogueId != null) {
            url = addDialogueIdToUrl(url);
        }
        String encodedUrl = response.encodeURL(url);
        try {
            response.sendRedirect(encodedUrl);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String addDialogueIdToUrl(String url) {
        if (dialogueId != null) {
            String paramName = DialogueFilter.DIALOGUE_ID_PARAM;
            int queryStringIndex = url.indexOf("?");
            if (queryStringIndex < 0 || url.indexOf(paramName + "=", queryStringIndex) < 0) {
                url = new StringBuilder(url).append(queryStringIndex < 0 ? "?" : "&").append(paramName).append("=").append(dialogueId).toString();
            }
        }
        return url;
    }
}
