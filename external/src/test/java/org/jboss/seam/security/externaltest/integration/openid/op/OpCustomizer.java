package org.jboss.seam.security.externaltest.integration.openid.op;

import javax.enterprise.event.Observes;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.openid.api.OpenIdProviderConfigurationApi;
import org.jboss.solder.servlet.event.Initialized;

public class OpCustomizer {
    public void servletInitialized(@Observes @Initialized final ServletContext context, OpenIdProviderConfigurationApi op) {
        op.setHostName("localhost");
        op.setProtocol("http");
        op.setPort(8080);
    }
}
