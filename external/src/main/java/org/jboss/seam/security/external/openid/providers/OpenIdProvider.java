package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Base interface for defining a set of built in Open ID providers
 *
 * @author Shane Bryzak
 */
public interface OpenIdProvider {
    String getCode();

    String getName();

    String getUrl();
    
    void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes);
}
