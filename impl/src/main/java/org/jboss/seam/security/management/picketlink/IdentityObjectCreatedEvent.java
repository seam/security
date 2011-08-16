package org.jboss.seam.security.management.picketlink;

/**
 * This CDI event is raised when an identity object is created
 * 
 * @author Shane Bryzak
 *
 */
public class IdentityObjectCreatedEvent {
    private Object identityObject;
    
    public IdentityObjectCreatedEvent(Object identityObject) {
        this.identityObject = identityObject;
    }
    
    public Object getIdentityObject() {
        return identityObject;
    }
}
