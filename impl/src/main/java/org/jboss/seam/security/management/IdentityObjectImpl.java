package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.common.exception.PolicyValidationException;
import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 * Based implementation of IdentityObject
 *
 * @author Shane Bryzak
 */
public class IdentityObjectImpl implements IdentityObject, Serializable {
    private static final long serialVersionUID = -7880202628037808071L;

    private String id;
    private String name;
    private IdentityObjectType type;

    public IdentityObjectImpl(String id, String name, IdentityObjectType type) {
        if (name == null) throw new IllegalArgumentException("IdentityObject.name cannot be null");
        if (type == null) throw new IllegalArgumentException("IdentityObject.identityType cannot be null");

        this.id = id;
        this.name = name;
        this.type = type;
    }

    public String getId() {
        return id;
    }

    public IdentityObjectType getIdentityType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public void validatePolicy() throws PolicyValidationException {

    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof IdentityObject)) return false;
        IdentityObject other = (IdentityObject) value;

        return (id != null ? id.equals(other.getId()) : other.getId() == null) &&
                name.equals(other.getName()) &&
                type.equals(other.getIdentityType());
    }

    @Override
    public int hashCode() {
        int hash = 0;
        if (id != null) hash ^= (id.hashCode() * 17);
        hash ^= (name.hashCode() * 29) ^ (type.hashCode() * 37);
        return hash;
    }
}
