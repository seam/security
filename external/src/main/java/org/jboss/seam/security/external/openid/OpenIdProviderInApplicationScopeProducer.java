package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

/**
 * @author Marcel Kolsteren
 * 
 */
@Alternative
public class OpenIdProviderInApplicationScopeProducer
{
   @Produces
   @ApplicationScoped
   public OpenIdProviderBean produce(@New OpenIdProviderBean op)
   {
      return op;
   }
}
