package org.jboss.seam.security.externaltest.integration.openid.op;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;

@ApplicationScoped
public class OpenIdProviderApplicationMock implements OpenIdProviderSpi {
    @Inject
    private OpenIdProviderApi opApi;

    private String dialogueId;

    @Inject
    private Dialogue dialogue;

    @Inject
    private DialogueManager dialogueManager;

    public void handleLogin(String userName, HttpServletResponse response) {
        dialogueManager.attachDialogue(dialogueId);
        opApi.authenticationSucceeded(userName, response);
        dialogueManager.detachDialogue();
    }

    public void setAttribute(String alias, String value, HttpServletResponse response) {
        dialogueManager.attachDialogue(dialogueId);
        Map<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put(alias, new ArrayList<String>());
        attributes.get(alias).add(value);
        opApi.setAttributes(attributes, response);
        dialogueManager.detachDialogue();
    }

    public void authenticate(String realm, String userName, boolean immediate, ResponseHolder responseHolder) {
        if (userName == null) {
            writeMessageToResponse("Please login.", responseHolder);
        } else {
            writeMessageToResponse("Please provide the password for " + userName + ".", responseHolder);
        }
        dialogueId = dialogue.getId();
    }

    private void writeMessageToResponse(String message, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().getWriter().print(message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean userExists(String userName) {
        return true;
    }

    public void fetchParameters(List<OpenIdRequestedAttribute> requestedAttributes, ResponseHolder responseHolder) {
        writeMessageToResponse("Please provide your " + requestedAttributes.get(0).getAlias() + ".", responseHolder);
        dialogueId = dialogue.getId();
    }
}
