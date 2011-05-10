package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 * Simple implementation of IdentityObjectType
 *
 * @author Shane Bryzak
 */
public class IdentityObjectTypeImpl implements IdentityObjectType, Serializable {
    private static final long serialVersionUID = -4364461076493738717L;

    private String name;

    public IdentityObjectTypeImpl(String name) {
        if (name == null) throw new IllegalArgumentException("IdentityObjectType name cannot be null");
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof IdentityObjectType)) return false;
        IdentityObjectType other = (IdentityObjectType) value;
        return name.equals(other.getName());
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
