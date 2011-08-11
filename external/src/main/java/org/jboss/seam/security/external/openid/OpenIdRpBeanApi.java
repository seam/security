package org.jboss.seam.security.external.openid;

import java.io.Writer;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyConfigurationApi;

/**
 * @author Marek Schmidt (maschmid AT redhat.com)
 */
public interface OpenIdRpBeanApi extends OpenIdRelyingPartyApi, OpenIdRelyingPartyConfigurationApi {
    String getServiceURL(OpenIdService service);
    void writeRpXrds(Writer writer);
}
