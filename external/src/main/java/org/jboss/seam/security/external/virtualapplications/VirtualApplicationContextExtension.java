package org.jboss.seam.security.external.virtualapplications;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;

/**
 * @author Marcel Kolsteren
 */
public class VirtualApplicationContextExtension implements Extension {
    private VirtualApplicationContext virtualApplicationContext;

    public void afterBeanDiscovery(@Observes AfterBeanDiscovery event, BeanManager manager) {
        virtualApplicationContext = new VirtualApplicationContext();
        event.addContext(virtualApplicationContext);
    }

    public VirtualApplicationContext getVirtualApplicationContext() {
        return virtualApplicationContext;
    }

}
