package org.jboss.seam.security.external;

import org.jboss.seam.security.external.saml.api.SamlNameId;

/**
 * @author Marcel Kolsteren
 */
public class SamlNameIdImpl implements SamlNameId {
    private String value;

    private String format;

    private String qualifier;

    public SamlNameIdImpl(String value, String format, String qualifier) {
        super();
        this.value = value;
        this.format = format;
        this.qualifier = qualifier;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getQualifier() {
        return qualifier;
    }

    public void setQualifier(String qualifier) {
        this.qualifier = qualifier;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((format == null) ? 0 : format.hashCode());
        result = prime * result + ((qualifier == null) ? 0 : qualifier.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
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
        SamlNameIdImpl other = (SamlNameIdImpl) obj;
        if (format == null) {
            if (other.format != null)
                return false;
        } else if (!format.equals(other.format))
            return false;
        if (qualifier == null) {
            if (other.qualifier != null)
                return false;
        } else if (!qualifier.equals(other.qualifier))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

}
