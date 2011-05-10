package org.jboss.seam.security.external.saml.sp;

import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

import org.jboss.seam.security.external.virtualapplications.api.VirtualApplication;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplicationScoped;

/**
 * @author Marcel Kolsteren
 */
@Alternative
public class SamlSpInVirtualApplicationScopeProducer {
    @Produces
    @VirtualApplicationScoped
    public SamlSpBean produceSp(@New SamlSpBean sp, VirtualApplication virtualApplication) {
        String hostName = virtualApplication.getHostName();
        sp.setHostName(hostName);
        sp.setEntityId("https://" + hostName);

        return sp;
    }
}
