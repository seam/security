package org.jboss.seam.security.examples.id_provider;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.api.ResponseHolder;
import org.jboss.seam.security.external.saml.api.SamlIdentityProviderApi;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.spi.SamlIdentityProviderSpi;

public class SamlIdentityProviderSpiImpl implements SamlIdentityProviderSpi {
    @Inject
    private Logger log;

    @Inject
    private ServletContext servletContext;

    @Inject
    private SamlIdentity identity;

    @Inject
    private SamlIdentityProviderApi idpApi;

    public void authenticate(ResponseHolder responseHolder) {
        if (identity.isLoggedIn()) {
            idpApi.authenticationSucceeded(responseHolder.getResponse());
        } else {
            responseHolder.redirectWithDialoguePropagation(servletContext.getContextPath() + "/Login.jsf");
        }
    }

    public void globalLogoutFailed(ResponseHolder responseHolder) {
        try {
            responseHolder.getResponse().sendRedirect(servletContext.getContextPath() + "/SingleLogoutFailed.jsf");
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

    public void loggedOut(SamlIdpSession session) {
        log.info("Unsolicited logout for user " + session.getPrincipal().getNameId().getValue() + ".");
    }
}
