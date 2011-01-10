package org.jboss.seam.security.external.openid.providers;

import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

/**
 * A producer that returns a list of open id providers, useful for building 
 * web interfaces
 * 
 * @author Shane Bryzak
 *
 */
public @ApplicationScoped class OpenIdProviderListProducer
{
   @Inject Instance<OpenIdProvider> providerInstances;
   
   private List<OpenIdProvider> providers;
   
   @Inject public void init()
   {
      providers = new ArrayList<OpenIdProvider>();
      
      for (OpenIdProvider provider : providerInstances)
      {
         providers.add(provider);
      }
   }
   
   @Produces public List<OpenIdProvider> listProviders()
   {
      return providers;
   }
}
