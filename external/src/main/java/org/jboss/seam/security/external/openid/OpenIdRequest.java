package org.jboss.seam.security.external.openid;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;

import org.openid4java.discovery.DiscoveryInformation;

/**
 * @author Marcel Kolsteren
 */
@SessionScoped
public class OpenIdRequest implements Serializable {
    private static final long serialVersionUID = -6701058408595984106L;

    private DiscoveryInformation discoveryInformation;

    public DiscoveryInformation getDiscoveryInformation() {
        return discoveryInformation;
    }

    public void setDiscoveryInformation(DiscoveryInformation discoveryInformation) {
        this.discoveryInformation = discoveryInformation;
    }
}
