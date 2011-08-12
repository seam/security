package org.jboss.seam.security.external.openid;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;
import org.jboss.seam.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class OpenIdProviderInVirtualApplicationScopeProducer {
    @Produces
    @VirtualApplicationScoped
    public OpenIdProviderBean produce(@New OpenIdProviderBean op) {
        return op;
    }
}
