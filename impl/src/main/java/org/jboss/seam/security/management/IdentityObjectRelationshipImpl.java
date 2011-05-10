package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectRelationship;
import org.picketlink.idm.spi.model.IdentityObjectRelationshipType;

/**
 * @author Shane Bryzak
 */
public class IdentityObjectRelationshipImpl implements IdentityObjectRelationship, Serializable {
    private static final long serialVersionUID = 487517126125658201L;

    private IdentityObject fromIdentityObject;
    private IdentityObject toIdentityObject;
    private String name;
    private IdentityObjectRelationshipType type;

    public IdentityObjectRelationshipImpl(IdentityObject fromIdentityObject,
                                          IdentityObject toIdentityObject, String name,
                                          IdentityObjectRelationshipType type) {
        if (fromIdentityObject == null)
            throw new IllegalArgumentException("IdentityObjectRelationship.fromIdentityObject cannot be null.");
        if (toIdentityObject == null)
            throw new IllegalArgumentException("IdentityObjectRelationship.toIdentityObject cannot be null.");
        if (type == null) throw new IllegalArgumentException("IdentityObjectRelationship.type cannot be null.");

        this.fromIdentityObject = fromIdentityObject;
        this.toIdentityObject = toIdentityObject;
        this.name = name;
        this.type = type;
    }

    public IdentityObject getFromIdentityObject() {
        return fromIdentityObject;
    }

    public IdentityObject getToIdentityObject() {
        return toIdentityObject;
    }

    public String getName() {
        return name;
    }

    public IdentityObjectRelationshipType getType() {
        return type;
    }

    @Override
    public boolean equals(Object value) {
        if (!(value instanceof IdentityObjectRelationship)) return false;
        IdentityObjectRelationship other = (IdentityObjectRelationship) value;

        if (!fromIdentityObject.equals(other.getFromIdentityObject())) return false;
        if (!toIdentityObject.equals(other.getToIdentityObject())) return false;
        if (!type.equals(other.getType())) return false;
        if (name == null) {
            if (other.getName() != null) return false;
        } else {
            if (!name.equals(other.getName())) return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int hash = (fromIdentityObject.hashCode() * 11) ^
                (toIdentityObject.hashCode() * 17) ^
                (type.hashCode() * 23);

        if (name != null) hash ^= (name.hashCode() * 29);

        return hash;
    }
}
