package org.jboss.seam.security.external;

import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;

/**
 * @author Marcel Kolsteren
 */
public class OpenIdRequestedAttributeImpl implements OpenIdRequestedAttribute {
    private String alias;
    private String typeUri;
    private boolean required;
    private Integer count;

    public OpenIdRequestedAttributeImpl() {
    }

    public OpenIdRequestedAttributeImpl(String alias, String typeUri, boolean required, Integer count) {
        super();
        this.alias = alias;
        this.typeUri = typeUri;
        this.required = required;
        this.count = count;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getTypeUri() {
        return typeUri;
    }

    public void setTypeUri(String typeUri) {
        this.typeUri = typeUri;
    }

    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

}
