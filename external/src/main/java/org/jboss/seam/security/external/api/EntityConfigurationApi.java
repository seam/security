package org.jboss.seam.security.external.api;

/**
 * API for configuration of entities that play a role in distributed security
 * (examples of entities are SAML identity providers, SAML service providers,
 * OpenID relying parties and OpenID providers)
 *
 * @author Marcel Kolsteren
 */
public interface EntityConfigurationApi {
    /**
     * This property contains the protocol that is used by the entity. Either
     * "http" or "https".
     *
     * @return the protocol
     */
    String getProtocol();

    /**
     * See {@link #getProtocol}
     *
     * @param protocol protocol
     */
    void setProtocol(String protocol);

    /**
     * The host name which is used to access this application from a web browser
     * (by the end user).
     *
     * @return the host name
     */
    String getHostName();

    /**
     * See {@link #getHostName}
     *
     * @param hostName host name
     */
    void setHostName(String hostName);

    /**
     * The port at which this application is reachable from the browser of the
     * end user. This might be another port then the port where the web container
     * is listening to (in case of port forwarding). In most practical production
     * employments, this port will be the standard HTTPS port, being 443.
     *
     * @return
     */
    int getPort();

    /**
     * See {@link #getPort}
     *
     * @param port port
     */
    void setPort(int port);
}
