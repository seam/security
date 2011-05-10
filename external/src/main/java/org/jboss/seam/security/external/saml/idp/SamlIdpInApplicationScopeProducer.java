package org.jboss.seam.security.external.saml.idp;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

/**
 * @author Marcel Kolsteren
 */
@Alternative
public class SamlIdpInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public SamlIdpBean produce(@New SamlIdpBean idp) {
        return idp;
    }
}
