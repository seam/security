package org.jboss.seam.security.external.openid;

import java.io.Writer;

import org.jboss.seam.security.external.openid.api.OpenIdProviderApi;
import org.jboss.seam.security.external.openid.api.OpenIdProviderConfigurationApi;

/**
 * @author Marek Schmidt (maschmid AT redhat.com)
 */
public interface OpenIdProviderBeanApi extends OpenIdProviderApi, OpenIdProviderConfigurationApi {
    String getServiceURL(OpenIdService openIdService);
    String getUsersUrlPrefix();
    void writeClaimedIdentifierXrds(Writer writer, String opLocalIdentifier);
    String getUserNameFromOpLocalIdentifier(String opLocalIdentifier);
    void writeOpIdentifierXrds(Writer writer);
}
