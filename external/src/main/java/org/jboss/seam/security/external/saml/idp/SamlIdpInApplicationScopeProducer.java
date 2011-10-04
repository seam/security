package org.jboss.seam.security.external.saml.idp;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class SamlIdpInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public SamlIdpBean produce(@New SamlIdpBean idp) {
        return idp;
    }
}
