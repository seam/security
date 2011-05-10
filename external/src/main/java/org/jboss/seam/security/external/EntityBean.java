package org.jboss.seam.security.external;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * @author Marcel Kolsteren
 */
public abstract class EntityBean {

    protected String hostName;
    protected String protocol = "https";
    protected int port = 443;

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    protected String createURL(String path) {
        try {
            if (protocol.equals("http") && port == 80 || protocol.equals("https") && port == 443) {
                return new URL(protocol, hostName, path).toExternalForm();
            } else {
                return new URL(protocol, hostName, port, path).toExternalForm();
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
