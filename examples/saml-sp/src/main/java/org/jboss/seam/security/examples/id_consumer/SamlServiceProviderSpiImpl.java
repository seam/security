package org.jboss.seam.security.examples.id_consumer;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderApi;
import org.jboss.seam.security.external.saml.api.SamlSpSession;
import org.jboss.seam.security.external.spi.SamlServiceProviderSpi;

public class SamlServiceProviderSpiImpl implements SamlServiceProviderSpi {
    @Inject
    SamlServiceProviderApi samlServiceProviderApi;

    @Inject
    private Logger log;

    @Inject
    private ServletContext servletContext;

    public void loginSucceeded(SamlSpSession session, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/UserInfo.jsf");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void loginFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/AuthenticationFailed.jsf");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void globalLogoutFailed(String statusCodeLevel1, String statusCodeLevel2, ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/GlobalLogoutFailed.jsf");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void globalLogoutSucceeded(ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/Login.jsf");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void loggedIn(SamlSpSession session, String url, ResponseHolder responseHolder) {
        try {
            if (url != null) {
                responseHolder.getResponse().sendRedirect(url);
            } else {
                responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/UserInfo.jsf");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void loggedOut(SamlSpSession session) {
        log.info("User " + session.getPrincipal().getNameId() + " has been logged out.");
    }
}
