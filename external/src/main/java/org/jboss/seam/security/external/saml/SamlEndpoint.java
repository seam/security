package org.jboss.seam.security.external.saml;

import org.jboss.seam.security.external.saml.api.SamlBinding;

/**
 * @author Marcel Kolsteren
 */
public class SamlEndpoint {
    private SamlBinding samlBinding;

    private String location;

    private String responseLocation;

    private SamlService service;

    public SamlEndpoint(SamlService service, SamlBinding samlBinding, String location, String responseLocation) {
        super();
        this.service = service;
        this.samlBinding = samlBinding;
        this.location = location;
        this.responseLocation = responseLocation;
    }

    public SamlService getService() {
        return service;
    }

    public SamlBinding getBinding() {
        return samlBinding;
    }

    public String getLocation() {
        return location;
    }

    public String getResponseLocation() {
        return responseLocation != null ? responseLocation : location;
    }
}
