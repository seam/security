package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObjectRelationshipType;

/**
 * Simple implementation of IdentityObjectRelationshipType
 *
 * @author Shane Bryzak
 */
public class IdentityObjectRelationshipTypeImpl implements IdentityObjectRelationshipType, Serializable {
    private static final long serialVersionUID = 6389479876202629001L;

    private String name;

    public IdentityObjectRelationshipTypeImpl(String name) {
        if (name == null) throw new IllegalArgumentException("IdentityObjectRelationshipType.name cannot be null.");

        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof IdentityObjectRelationshipType)) return false;
        IdentityObjectRelationshipType other = (IdentityObjectRelationshipType) value;

        return name.equals(other.getName());
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
