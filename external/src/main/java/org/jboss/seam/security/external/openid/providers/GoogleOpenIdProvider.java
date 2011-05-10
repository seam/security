package org.jboss.seam.security.external.openid.providers;

/**
 * Open ID provider for Google Accounts
 *
 * @author Shane Bryzak
 */
public class GoogleOpenIdProvider implements OpenIdProvider {
    public static final String CODE = "google";

    public String getCode() {
        return CODE;
    }

    public String getName() {
        return "Google";
    }

    public String getUrl() {
        return "https://www.google.com/accounts/o8/id";
    }

}
