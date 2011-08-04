package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Open ID provider for myopenid.com
 *
 * @author Shane Bryzak
 */
public class MyOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "myopenid";

    public String getCode() {
        return CODE;
    }

    public String getName() {
        return "MyOpenID";
    }

    public String getUrl() {
        return "https://myopenid.com";
    }

    public void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes) {
        
    }
}
