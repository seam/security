package org.jboss.seam.security.external.openid;

import javax.enterprise.context.ApplicationScoped;

/**
 * This bean should be configured in seam-beans.xml using Seam Config to set the
 * local hostname, port and protocol to use for OpenID authentication.
 * 
 * @author Shane Bryzak
 *
 */
@ApplicationScoped
public class OpenIdConfiguration {
    
    private String hostName;
    private int port = 443;    
    private String protocol = "https";
    private String returnToPath = null;
    
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
    
    public String getProtocol() {
        return protocol;
    }
    
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getReturnToPath() {
        return returnToPath;
    }

    public void setReturnToPath(String returnToPath) {
        this.returnToPath = returnToPath;
    }

}
