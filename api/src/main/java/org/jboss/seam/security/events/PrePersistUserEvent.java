package org.jboss.seam.security.events;

/**
 * This event is raised just before a new user is persisted
 *
 * @author Shane Bryzak
 */
public class PrePersistUserEvent {
    private Object user;

    public PrePersistUserEvent(Object user) {
        this.user = user;
    }

    public Object getUser() {
        return user;
    }
}
