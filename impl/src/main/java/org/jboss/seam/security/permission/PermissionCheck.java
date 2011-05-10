package org.jboss.seam.security.permission;

import java.util.HashSet;
import java.util.Set;

/**
 * Used to assert permission check requirements into a StatefulSession when evaluating
 * a @Restrict expression.  The consequence of the rule is responsible for
 * granting the permission.
 *
 * @author Shane Bryzak
 */
public class PermissionCheck {
    private Object resource;

    private String permission;
    private boolean granted;
    private Set<String> requirements;

    public PermissionCheck(Object resource, String permission) {
        this.resource = resource;
        this.permission = permission;
        granted = false;
    }

    public Object getResource() {
        return resource;
    }

    public String getPermission() {
        return permission;
    }

    public void require(String requirement) {
        if (requirements == null) {
            requirements = new HashSet<String>();
        }

        requirements.add(requirement);
    }

    public void grant() {
        this.granted = true;
    }

    public void revoke() {
        this.granted = false;
    }

    public boolean isGranted() {
        return granted;
    }

    public boolean hasRequirements() {
        return requirements != null && requirements.size() > 0;
    }

    public Set<String> getRequirements() {
        return requirements;
    }
}
