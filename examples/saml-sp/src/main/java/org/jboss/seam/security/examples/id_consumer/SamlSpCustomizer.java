package org.jboss.seam.security.examples.id_consumer;

import javax.enterprise.event.Observes;

import org.jboss.seam.security.external.saml.api.SamlServiceProviderConfigurationApi;
import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationCreation;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplication;

public class SamlSpCustomizer {
    public void customize(@Observes AfterVirtualApplicationCreation event, SamlServiceProviderConfigurationApi sp, VirtualApplication virtualApplication) {
        sp.setEntityId("http://" + virtualApplication.getHostName());
        sp.setProtocol("http");
        sp.setPort(8080);
        sp.setSigningKey("classpath:/test_keystore.jks", "store456", "servercert", "pass456");
    }

}
