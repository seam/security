package org.jboss.seam.security.externaltest.integration.openid.rp;

import javax.enterprise.event.Observes;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyConfigurationApi;
import org.jboss.solder.servlet.event.Initialized;

public class RpCustomizer {
    public void servletInitialized(@Observes @Initialized final ServletContext context, OpenIdRelyingPartyConfigurationApi rp) {
        rp.setHostName("localhost");
        rp.setProtocol("http");
        rp.setPort(8080);
    }
}
