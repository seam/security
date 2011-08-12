package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.seam.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class OpenIdRpInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public OpenIdRpBean produce(@New OpenIdRpBean rp)
    {
       return rp;
    }
}
