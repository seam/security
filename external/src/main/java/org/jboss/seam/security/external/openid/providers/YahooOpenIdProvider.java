package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Open ID provider for Yahoo accounts
 *
 * @author Shane Bryzak
 */
public class YahooOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "yahoo";

    public String getCode() {
        return CODE;
    }

    public String getName() {
        return "Yahoo";
    }

    public String getUrl() {
        return "https://me.yahoo.com";
    }
    
    public void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes) {
        
        
    }
}
