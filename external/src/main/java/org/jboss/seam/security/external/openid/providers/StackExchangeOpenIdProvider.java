package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Open ID provider for StackExchange Accounts
 * 
 * @author <a href="mailto:lincolnbaxter@gmail.com">Lincoln Baxter, III</a>
 */
public class StackExchangeOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "stackexchange";

    private boolean requestFirstName = true;
    private boolean requestLastName = true;
    private boolean requestEmail = true;

    public boolean isRequestFirstName() {
        return requestFirstName;
    }

    public void setRequestFirstName(boolean value) {
        this.requestFirstName = value;
    }

    public boolean isRequestLastName() {
        return requestLastName;
    }

    public void setRequestLastName(boolean value) {
        this.requestLastName = value;
    }

    public boolean isRequestEmail() {
        return requestEmail;
    }

    public void setRequestEmail(boolean value) {
        this.requestEmail = value;
    }

    @Override
    public String getCode() {
        return CODE;
    }

    @Override
    public String getName() {
        return "StackExchange";
    }

    @Override
    public String getUrl() {
        return "https://openid.stackexchange.com/";
    }

    @Override
    public void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes) {
    }
}
