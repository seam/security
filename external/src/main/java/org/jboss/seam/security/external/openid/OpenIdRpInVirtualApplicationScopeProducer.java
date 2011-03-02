package org.jboss.seam.security.external.openid;

import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * @author Marcel Kolsteren
 * 
 */
@Alternative
public class OpenIdRpInVirtualApplicationScopeProducer
{
   @Produces
   @VirtualApplicationScoped
   public OpenIdRpBean produce(@New OpenIdRpBean rp)
   {
      return rp;
   }
}
