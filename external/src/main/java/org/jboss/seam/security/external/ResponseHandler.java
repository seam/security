package org.jboss.seam.security.external;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.saml.SamlMessage;
import org.jboss.seam.security.external.saml.SamlPostMessage;
import org.jboss.seam.security.external.saml.SamlRedirectMessage;

/**
 * @author Marcel Kolsteren
 */
public class ResponseHandler {
    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private Dialogue dialogue;

    public void sendFormToUserAgent(String destination, SamlPostMessage message, HttpServletResponse response) {
        String key = message.getRequestOrResponse().isRequest() ? SamlMessage.QSP_SAML_REQUEST : SamlMessage.QSP_SAML_RESPONSE;

        if (destination == null)
            throw new IllegalStateException("Destination is null");

        StringBuilder builder = new StringBuilder();

        builder.append("<HTML>");
        builder.append("<HEAD>");
        if (message.getRequestOrResponse().isRequest())
            builder.append("<TITLE>HTTP Post SamlBinding (Request)</TITLE>");
        else
            builder.append("<TITLE>HTTP Post SamlBinding Response (Response)</TITLE>");

        builder.append("</HEAD>");
        builder.append("<BODY Onload=\"document.forms[0].submit()\">");

        builder.append("<FORM METHOD=\"POST\" ACTION=\"" + destination + "\">");
        builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + key + "\"" + " VALUE=\"" + message.getSamlMessage() + "\"/>");
        if (message.getRelayState() != null) {
            builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"" + SamlMessage.QSP_RELAY_STATE + "\"" + " VALUE=\"" + message.getRelayState() + "\"/>");
        }
        builder.append("</FORM></BODY></HTML>");

        PrintWriter writer = getWriter(response);
        writer.print(builder.toString());
        writer.flush();
    }

    public void sendHttpRedirectToUserAgent(String url, HttpServletResponse response) {
        try {
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void sendHttpRedirectToUserAgent(String location, SamlRedirectMessage redirectMessage, HttpServletResponse response) {
        String url = location + "?" + redirectMessage.createQueryString();
        sendHttpRedirectToUserAgent(url, response);
    }

    public void sendError(int statusCode, String message, HttpServletResponse response) {
        try {
            response.sendError(statusCode, message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private PrintWriter getWriter(HttpServletResponse response) {
        try {
            return response.getWriter();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Writer getWriter(String mimeType, HttpServletResponse response) {
        response.setContentType(mimeType);
        return getWriter(response);
    }

    public ResponseHolderImpl createResponseHolder(HttpServletResponse response) {
        String dialogueId = null;
        if (dialogueManager.isAttached()) {
            dialogueId = dialogue.getId();
        }
        return new ResponseHolderImpl(response, dialogueId);
    }
}
