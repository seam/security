package org.jboss.seam.security.external.saml.sp;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

/**
 * @author Marcel Kolsteren
 * 
 */
@Alternative
public class SamlSpInApplicationScopeProducer
{
   @Produces
   @ApplicationScoped
   public SamlSpBean produceSp(@New SamlSpBean sp)
   {
      return sp;
   }
}
