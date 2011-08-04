package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import javax.enterprise.inject.Model;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * @author Shane Bryzak
 */
public
@Model
class CustomOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "custom";

    private String url;

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCode() {
        return CODE;
    }

    public String getName() {
        return "Custom";
    }

    public String getUrl() {
        return url;
    }
    
    public void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes) {
        
    }
}
