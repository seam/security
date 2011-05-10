package org.jboss.seam.security.externaltest.integration.openid.rp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdRelyingPartySpi;

public class OpenIdRpApplicationMock implements OpenIdRelyingPartySpi {
    @Inject
    private OpenIdRelyingPartyApi rpApi;

    @Dialogued
    public void login(String identifier, boolean fetchEmail, HttpServletResponse response) {
        if (fetchEmail) {
            OpenIdRequestedAttribute requestedAttribute = rpApi.createOpenIdRequestedAttribute("email", "http://axschema.org/contact/email", true, 1);
            List<OpenIdRequestedAttribute> requestedAttributes = new ArrayList<OpenIdRequestedAttribute>();
            requestedAttributes.add(requestedAttribute);
            rpApi.login(identifier, requestedAttributes, response);
        } else {
            rpApi.login(identifier, null, response);
        }
    }

    public void loginFailed(String message, ResponseHolder responseHolder) {
        writeMessageToResponse("Login failed: " + message, responseHolder);
    }

    public void loginSucceeded(OpenIdPrincipal principal, ResponseHolder responseHolder) {
        if (principal.getAttributeValues() != null) {
            String email = (String) principal.getAttribute("email");
            writeMessageToResponse("Login succeeded (" + principal.getIdentifier() + ", email " + email + ")", responseHolder);
        } else {
            writeMessageToResponse("Login succeeded (" + principal.getIdentifier() + ")", responseHolder);
        }
    }

    private void writeMessageToResponse(String message, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().getWriter().print(message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
