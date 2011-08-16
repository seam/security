package org.jboss.seam.security.events;

/**
 * This event should be fired when a deferred authentication process is complete
 *
 * @author Shane Bryzak
 */
public class DeferredAuthenticationEvent {
    
    private boolean success = false;
    
    public DeferredAuthenticationEvent(boolean success) {
        this.success = success;
    }
    
    public boolean isSuccess() {
        return success;
    }
}
