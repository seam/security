package org.jboss.seam.security.external;

import java.net.URL;
import java.util.List;
import java.util.Map;

import org.jboss.seam.security.external.openid.api.OpenIdPrincipal;

/**
 * @author Marcel Kolsteren
 */
public class OpenIdPrincipalImpl implements OpenIdPrincipal {
    private String identifier;

    private URL openIdProvider;

    private Map<String, List<String>> attributeValues;

    public OpenIdPrincipalImpl(String identifier, URL openIdProvider, Map<String, List<String>> attributeValues) {
        super();
        this.identifier = identifier;
        this.openIdProvider = openIdProvider;
        this.attributeValues = attributeValues;
    }

    public String getIdentifier() {
        return identifier;
    }

    public URL getOpenIdProvider() {
        return openIdProvider;
    }

    public Map<String, List<String>> getAttributeValues() {
        return attributeValues;
    }

    public String getAttribute(String alias) {
        if (attributeValues == null) return null;

        List<String> values = attributeValues.get(alias);
        if (values==null||values.size() == 0) {
            return null;
        } else if (values.size() == 1) {
            return (String) attributeValues.get(alias).get(0);
        } else {
            throw new RuntimeException("Attribute has multiple values");
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((identifier == null) ? 0 : identifier.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        OpenIdPrincipalImpl other = (OpenIdPrincipalImpl) obj;
        if (identifier == null) {
            if (other.identifier != null)
                return false;
        } else if (!identifier.equals(other.identifier))
            return false;
        return true;
    }
}
