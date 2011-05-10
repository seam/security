package org.jboss.seam.security.external.saml;

import java.util.LinkedList;
import java.util.List;

import org.jboss.seam.security.external.jaxb.samlv2.metadata.EndpointType;
import org.jboss.seam.security.external.saml.api.SamlBinding;

/**
 * @author Marcel Kolsteren
 */
public class SamlService {
    private SamlProfile profile;

    private List<SamlEndpoint> serviceEndpoints = new LinkedList<SamlEndpoint>();

    public SamlService(SamlProfile profile, List<? extends EndpointType> endpoints) {
        this.profile = profile;

        for (EndpointType endpoint : endpoints) {
            SamlBinding samlBinding = null;
            if (endpoint.getBinding().endsWith("HTTP-Redirect")) {
                samlBinding = SamlBinding.HTTP_Redirect;
            } else if (endpoint.getBinding().endsWith("HTTP-POST")) {
                samlBinding = SamlBinding.HTTP_Post;
            } else {
                // ignore other bindings
            }
            if (samlBinding != null) {
                SamlEndpoint samlEndpoint = new SamlEndpoint(this, samlBinding, endpoint.getLocation(), endpoint.getResponseLocation());
                serviceEndpoints.add(samlEndpoint);
            }
        }
    }

    public SamlProfile getProfile() {
        return profile;
    }

    public List<SamlEndpoint> getServiceEndpoints() {
        return serviceEndpoints;
    }

    public SamlEndpoint getEndpointForBinding(SamlBinding samlBinding) {
        for (SamlEndpoint endpoint : serviceEndpoints) {
            if (endpoint.getBinding() == samlBinding) {
                return endpoint;
            }
        }

        return null;
    }
}
