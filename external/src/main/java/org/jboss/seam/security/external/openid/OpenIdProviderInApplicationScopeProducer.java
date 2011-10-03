package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class OpenIdProviderInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public OpenIdProviderBean produce(@New OpenIdProviderBean op) {
        return op;
    }
}
