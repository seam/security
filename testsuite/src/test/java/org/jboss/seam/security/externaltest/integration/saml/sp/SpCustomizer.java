package org.jboss.seam.security.externaltest.integration.saml.sp;

import javax.enterprise.event.Observes;

import org.jboss.seam.security.external.saml.api.SamlBinding;
import org.jboss.seam.security.external.saml.api.SamlServiceProviderConfigurationApi;
import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationCreation;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplication;

public class SpCustomizer {
    public void customize(@Observes AfterVirtualApplicationCreation event, SamlServiceProviderConfigurationApi sp, VirtualApplication virtualApplication) {
        if (virtualApplication.getHostName().equals("www.sp2.com")) {
            sp.setPreferredBinding(SamlBinding.HTTP_Redirect);
        }
        sp.setSingleLogoutMessagesSigned(false);
        sp.setProtocol("http");
        sp.setPort(8080);
    }

}
