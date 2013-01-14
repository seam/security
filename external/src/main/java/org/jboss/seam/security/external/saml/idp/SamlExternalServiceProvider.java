package org.jboss.seam.security.external.saml.idp;

import java.util.HashMap;
import java.util.Map;

import org.jboss.seam.security.external.jaxb.samlv2.metadata.SPSSODescriptorType;
import org.jboss.seam.security.external.saml.SamlExternalEntity;
import org.jboss.seam.security.external.saml.SamlProfile;
import org.jboss.seam.security.external.saml.SamlService;

/**
 * @author Marcel Kolsteren
 */
public class SamlExternalServiceProvider extends SamlExternalEntity {
    private Map<SamlProfile, SamlService> services = new HashMap<SamlProfile, SamlService>();

    private boolean wantAssertionsSigned = true;

    private boolean authnRequestsSigned;

    public SamlExternalServiceProvider(String entityId, SPSSODescriptorType sPSSODescriptor) {
        super(entityId, sPSSODescriptor.getKeyDescriptor());

        wantAssertionsSigned = sPSSODescriptor.getWantAssertionsSigned();
        authnRequestsSigned = sPSSODescriptor.getAuthnRequestsSigned();

        services.put(SamlProfile.SINGLE_SIGN_ON, new SamlService(SamlProfile.SINGLE_SIGN_ON, sPSSODescriptor.getAssertionConsumerService()));
        services.put(SamlProfile.SINGLE_LOGOUT, new SamlService(SamlProfile.SINGLE_LOGOUT, sPSSODescriptor.getSingleLogoutService()));
    }

    public SamlService getService(SamlProfile service) {
        return services.get(service);
    }

    public boolean isWantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
        this.wantAssertionsSigned = wantAssertionsSigned;
    }

    public boolean isAuthnRequestsSigned() {
        return authnRequestsSigned;
    }

    public void setAuthnRequestsSigned(boolean authnRequestsSigned) {
        this.authnRequestsSigned = authnRequestsSigned;
    }
}
