package org.jboss.seam.security.external.openid;

/**
 * @author Marcel Kolsteren
 */
public enum OpenIdService {
    OPEN_ID_SERVICE("OpenIdService"),

    XRDS_SERVICE("XrdsService");

    private String name;

    private OpenIdService(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static OpenIdService getByName(String name) {
        for (OpenIdService service : values()) {
            if (service.getName().equals(name)) {
                return service;
            }
        }
        return null;
    }
}
