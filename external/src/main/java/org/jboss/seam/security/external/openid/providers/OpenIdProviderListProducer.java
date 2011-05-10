package org.jboss.seam.security.external.openid.providers;

import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

/**
 * A producer that returns a list of open id providers, useful for building
 * web interfaces
 *
 * @author Shane Bryzak
 */
public class OpenIdProviderListProducer {
    @Inject
    Instance<OpenIdProvider> providerInstances;

    @Produces
    @RequestScoped
    public List<OpenIdProvider> listProviders() {
        List<OpenIdProvider> providers = new ArrayList<OpenIdProvider>();

        for (OpenIdProvider provider : providerInstances) {
            providers.add(provider);
        }

        return providers;
    }
}
