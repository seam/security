package org.jboss.seam.security.external.virtualapplications.api;

/**
 * Event that is fired after the virtual application manager has been created.
 * Observers to this event can add virtual applications to the environment. For
 * details about how to use this event, refer to
 * {@link VirtualApplicationScoped}.
 *
 * @author Marcel Kolsteren
 */
public interface AfterVirtualApplicationManagerCreation {
    void addVirtualApplication(String hostName);
}
