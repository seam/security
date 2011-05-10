package org.jboss.seam.security.contexts;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;

import org.jboss.seam.security.AuthenticationScoped;

/**
 * An extension that enables @AuthenticationScoped beans
 *
 * @author Shane Bryzak
 */
public class AuthenticationScopedExtension implements Extension {
    public void addScope(@Observes final BeforeBeanDiscovery event) {
        event.addScope(AuthenticationScoped.class, true, false);
    }

    public void registerContext(@Observes final AfterBeanDiscovery event) {
        event.addContext(new AuthenticationContext());
    }
}
