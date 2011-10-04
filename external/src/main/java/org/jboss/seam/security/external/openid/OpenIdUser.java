package org.jboss.seam.security.external.openid;

import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;
import org.picketlink.idm.api.User;

/**
 * Represents a user authenticated using OpenID
 *
 * @author Shane Bryzak
 */
public class OpenIdUser implements User {
    private OpenIdPrincipal principal;

    public OpenIdUser(OpenIdPrincipal principal) {
        this.principal = principal;
    }

    public String getId() {
        return principal.getIdentifier();
    }

    public String getKey() {
        return getId();
    }

    public String getAttribute(String alias) {
        return principal.getAttribute(alias);
    }

    public String getProvider() {
        return principal.getOpenIdProvider().toString();
    }
}
