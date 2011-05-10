package org.jboss.seam.security.examples.id_consumer;

import javax.enterprise.event.Observes;

import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationManagerCreation;

/**
 * @author Marcel Kolsteren
 */
public class VirtualApplicationCreator {
    public void virtualApplicationManagerCreated(@Observes final AfterVirtualApplicationManagerCreation event) {
        event.addVirtualApplication("www.saml-sp1.com");
        event.addVirtualApplication("www.saml-sp2.com");
    }
}
