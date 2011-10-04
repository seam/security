package org.jboss.seam.security.external.openid.providers;

import java.util.List;

import org.jboss.seam.security.external.openid.api.OpenIdRelyingPartyApi;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * Open ID provider for Google Accounts
 *
 * @author Shane Bryzak
 */
public class GoogleOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "google";
    
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

    public String getCode() {
        return CODE;
    }

    public String getName() {
        return "Google";
    }

    public String getUrl() {
        return "https://www.google.com/accounts/o8/id";
    }
    
    public void requestAttributes(OpenIdRelyingPartyApi openIdApi, List<OpenIdRequestedAttribute> attributes) {
        //attributes.add(openIdApi.createOpenIdRequestedAttribute("openid.ns.ax", "http://openid.net/srv/ax/1.0", true, 1));

        if (requestEmail) {
            attributes.add(openIdApi.createOpenIdRequestedAttribute("email", "http://axschema.org/contact/email", true, 1));
        }
        
        if (requestFirstName) {
           attributes.add(openIdApi.createOpenIdRequestedAttribute("firstName", "http://axschema.org/namePerson/first", true, 1));           
        }
        
        if (requestLastName) {
            attributes.add(openIdApi.createOpenIdRequestedAttribute("lastName", "http://axschema.org/namePerson/last", true, 1));
        }            
    }
}
