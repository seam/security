package org.jboss.seam.security.events;

import org.picketlink.idm.api.User;

/**
 * This event is raised when user successfully logs in.
 *
 * @author Shane Bryzak
 */
public class LoggedInEvent {
    private User user;

    public LoggedInEvent(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}
