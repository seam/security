package org.jboss.seam.security.external.saml.sp;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.solder.core.Veto;

/**
 * @author Marcel Kolsteren
 */
@Veto
public class SamlSpInApplicationScopeProducer {
    @Produces
    @ApplicationScoped
    public SamlSpBean produceSp(@New SamlSpBean sp) {
        return sp;
    }
}
