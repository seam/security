package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.solder.core.Veto;

/**
 * Either this producer bean or OpenIdRpInVirtualApplicationScopeProducer MUST be enabled via
 * seam-config to allow OpenID authentication.
 * 
 * @author Marcel Kolsteren
 */
public class OpenIdRpInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public OpenIdRpBean produce(@New OpenIdRpBean rp)
    {
       return rp;
    }
}
