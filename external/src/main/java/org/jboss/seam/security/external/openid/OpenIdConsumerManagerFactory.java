package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.openid4java.consumer.ConsumerManager;

/**
 * @author Marcel Kolsteren
 */
@ApplicationScoped
public class OpenIdConsumerManagerFactory {
    private ConsumerManager consumerManager;

    @Produces
    public ConsumerManager getConsumerManager() {
        return consumerManager;
    }

    @Inject
    public void startup() throws Exception {
        consumerManager = new ConsumerManager();
    }
}
