package org.jboss.seam.security.events;

/**
 * This event is raised immediately after a user is created
 *
 * @author Shane Bryzak
 */
public class UserCreatedEvent {
    private Object user;

    public UserCreatedEvent(Object user) {
        this.user = user;
    }

    public Object getUser() {
        return user;
    }
}
