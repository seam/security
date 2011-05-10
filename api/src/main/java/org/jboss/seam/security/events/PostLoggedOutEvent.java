package org.jboss.seam.security.events;

import org.picketlink.idm.api.User;

/**
 * This event is raised just after the user unauthenticates
 *
 * @author Shane Bryzak
 */
public class PostLoggedOutEvent {
    private User user;

    public PostLoggedOutEvent(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}
