package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.openid4java.server.ServerManager;

/**
 * @author Marcel Kolsteren
 * 
 */
@ApplicationScoped
public class OpenIdServerManagerFactory
{
   private ServerManager serverManager;

   @Inject
   private OpenIdProviderBean providerBean;

   @Produces
   public ServerManager getServerManager()
   {
      return serverManager;
   }

   @Inject
   public void startup() throws Exception
   {
      serverManager = new ServerManager();
      serverManager.setOPEndpointUrl(providerBean.getServiceURL(OpenIdService.OPEN_ID_SERVICE));
   }
}