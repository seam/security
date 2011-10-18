package org.jboss.seam.security.externaltest.integration.saml.sp;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationManagerCreation;

@ApplicationScoped
public class SpVirtualApplicationCreator {
    public void virtualApplicationManagerCreated(@Observes final AfterVirtualApplicationManagerCreation event) {
        event.addVirtualApplication("www.sp1.com");
        event.addVirtualApplication("www.sp2.com");
    }
}
