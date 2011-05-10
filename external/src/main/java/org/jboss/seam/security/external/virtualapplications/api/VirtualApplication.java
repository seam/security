package org.jboss.seam.security.external.virtualapplications.api;

/**
 * This virtual application scoped bean is automatically created in the virtual
 * application scope as soon as the virtual application is created. It can be
 * used to get virtual application properties. For background about the virtual
 * application scope, see {@link VirtualApplicationScoped}.
 *
 * @author Marcel Kolsteren
 */
public interface VirtualApplication {
    String getHostName();
}
