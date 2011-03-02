package org.jboss.seam.security.examples.openid;

import javax.enterprise.event.Observes;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.openid.api.OpenIdProviderConfigurationApi;
import org.jboss.seam.servlet.event.Initialized;

public class OpenIdProviderCustomizer
{
   public void servletInitialized(@Observes @Initialized final ServletContext context, OpenIdProviderConfigurationApi op)
   {
      op.setHostName("www.openid-op.com");
      op.setPort(8080);
      op.setProtocol("http");
   }

}
