package org.jboss.seam.security.events;

/**
 * This event is raised just before a user role is persisted
 *
 * @author Shane Bryzak
 */
public class PrePersistUserRoleEvent {
    private Object xref;

    public PrePersistUserRoleEvent(Object xref) {
        this.xref = xref;
    }

    public Object getXref() {
        return xref;
    }
}
