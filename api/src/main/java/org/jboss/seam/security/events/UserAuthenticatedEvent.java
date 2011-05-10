package org.jboss.seam.security.events;

/**
 * This event is raised when a user is authenticated
 *
 * @author Shane Bryzak
 */
public class UserAuthenticatedEvent {
    private Object user;

    public UserAuthenticatedEvent(Object user) {
        this.user = user;
    }

    public Object getUser() {
        return user;
    }
}
