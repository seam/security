package org.jboss.seam.security.external.virtualapplications;

import java.util.HashSet;
import java.util.Set;

import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationManagerCreation;

/**
 * @author Marcel Kolsteren
 */
public class AfterVirtualApplicationManagerCreationEvent implements AfterVirtualApplicationManagerCreation {
    private Set<String> hostNames = new HashSet<String>();

    public void addVirtualApplication(String hostName) {
        hostNames.add(hostName);
    }

    public Set<String> getHostNames() {
        return hostNames;
    }

}
