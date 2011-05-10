package org.jboss.seam.security.external.saml;

/**
 * @author Marcel Kolsteren
 */
public enum SamlServiceType {
    SAML_SINGLE_SIGN_ON_SERVICE("SingleSignOnService", SamlProfile.SINGLE_SIGN_ON),

    SAML_ASSERTION_CONSUMER_SERVICE("AssertionConsumerService", SamlProfile.SINGLE_SIGN_ON),

    SAML_SINGLE_LOGOUT_SERVICE("SingleLogoutService", SamlProfile.SINGLE_LOGOUT),

    SAML_META_DATA_SERVICE("MetaDataService", null);

    private String name;

    private SamlProfile profile;

    private SamlServiceType(String name, SamlProfile profile) {
        this.name = name;
        this.profile = profile;
    }

    public String getName() {
        return name;
    }

    public SamlProfile getProfile() {
        return profile;
    }

    public static SamlServiceType getByName(String name) {
        for (SamlServiceType service : values()) {
            if (service.getName().equals(name)) {
                return service;
            }
        }
        return null;
    }
}
