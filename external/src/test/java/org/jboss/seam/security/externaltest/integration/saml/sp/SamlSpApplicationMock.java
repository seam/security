package org.jboss.seam.security.externaltest.integration.saml.sp;

import java.io.IOException;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.SamlMultiUserServiceProviderApi;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.dialogues.api.Dialogued;
import org.jboss.seam.security.external.saml.api.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

@VirtualApplicationScoped
public class SamlSpApplicationMock implements SamlServiceProviderSpi {
    @Inject
    private Instance<SamlMultiUserServiceProviderApi> spApi;

    @Inject
    private Logger log;

    @Dialogued
    public void login(String idpEntityId, HttpServletResponse response) {
        spApi.get().login(idpEntityId, response);
    }

    public void loginFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder) {
        writeMessageToResponse("login failed", responseHolder);
    }

    public void loginSucceeded(SamlSpSession session, ResponseHolder responseHolder) {
        writeMessageToResponse("Login succeeded (" + session.getPrincipal().getNameId().getValue() + ")", responseHolder);
    }

    public void globalLogoutFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder) {
        writeMessageToResponse("Single logout failed", responseHolder);
    }

    public void globalLogoutSucceeded(ResponseHolder responseHolder) {
        writeMessageToResponse("Single logout succeeded", responseHolder);
    }

    public void loggedIn(SamlSpSession session, String url, ResponseHolder responseHolder) {
        writeMessageToResponse("Logged in unsolicited", responseHolder);
    }

    private void writeMessageToResponse(String message, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().getWriter().print(message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public int getNumberOfSessions() {
        return spApi.get().getSessions().size();
    }

    @Dialogued
    public void handleGlobalLogout(HttpServletResponse response) {
        SamlSpSession session = spApi.get().getSessions().iterator().next();
        spApi.get().globalLogout(session, response);
    }

    public void loggedOut(SamlSpSession session) {
        log.info("User " + session.getPrincipal().getNameId() + " has been logged out.");
    }
}
