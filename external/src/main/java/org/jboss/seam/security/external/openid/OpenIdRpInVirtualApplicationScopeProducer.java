package org.jboss.seam.security.external.openid;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;
import org.jboss.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class OpenIdRpInVirtualApplicationScopeProducer {
    @Produces
    @VirtualApplicationScoped
    public OpenIdRpBean produce(@New OpenIdRpBean rp) {
        return rp;
    }
}
