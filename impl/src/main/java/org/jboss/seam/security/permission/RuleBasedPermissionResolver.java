package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.drools.ClassObjectFilter;
import org.drools.KnowledgeBase;
import org.drools.runtime.StatefulKnowledgeSession;
import org.drools.runtime.rule.FactHandle;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.events.PostAuthenticateEvent;
import org.jboss.seam.security.events.PostLoggedOutEvent;
import org.jboss.seam.security.qualifiers.Security;
import org.jboss.solder.core.Requires;
import org.jboss.solder.logging.Logger;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.Role;

/**
 * A permission resolver that uses a Drools rule base to perform permission checks
 *
 * @author Shane Bryzak
 */
@Requires("org.drools.KnowledgeBase")
@SessionScoped
public class RuleBasedPermissionResolver implements PermissionResolver, Serializable {
    private static final long serialVersionUID = -7572627522601793024L;

    private StatefulKnowledgeSession securityContext;
    
    @Inject Logger log;
   
    @Inject SecurityRuleLoader securityRuleLoader;

    @Inject BeanManager manager;
    
    @Inject Identity identity;    

    @Inject
    public void init() {
        if (getSecurityRules() != null) {
            setSecurityContext(getSecurityRules().newStatefulKnowledgeSession());
            //getSecurityContext().setGlobalResolver(new SeamGlobalResolver(getSecurityContext().getGlobalResolver()));
        }
    }

    /**
     * Performs a permission check for the specified name and action
     *
     * @param target Object The target of the permission check
     * @param action String The action to be performed on the target
     * @return boolean True if the user has the specified permission
     */
    public boolean hasPermission(Object resource, String permission) {
        if (getSecurityRules() == null) return false;
        
        StatefulKnowledgeSession securityContext = getSecurityContext();

        if (securityContext == null) return false;

        List<FactHandle> handles = new ArrayList<FactHandle>();

        PermissionCheck check;

        synchronized (securityContext) {
            if (!(resource instanceof String) && !(resource instanceof Class<?>)) {
                handles.add(securityContext.insert(resource));
            } else if (resource instanceof Class<?>) {
                // TODO fix
                String componentName = null; // manager. Seam.getComponentName((Class) target);
                resource = componentName != null ? componentName : ((Class<?>) resource).getName();
            }

            check = new PermissionCheck(resource, permission);

            try {
                synchronizeContext();

                handles.add(securityContext.insert(check));

                securityContext.fireAllRules();
            } finally {
                for (FactHandle handle : handles) {
                    securityContext.retract(handle);
                }
            }
        }

        return check.isGranted();
    }

    public void filterSetByAction(Set<Object> targets, String action) {
        Iterator<?> iter = targets.iterator();
        while (iter.hasNext()) {
            Object target = iter.next();
            if (hasPermission(target, action)) iter.remove();
        }
    }

    public boolean checkConditionalRole(String roleName, Object target, String action) {
        if (getSecurityRules() == null) return false;
        
        StatefulKnowledgeSession securityContext = getSecurityContext();
        if (securityContext == null) return false;

        RoleCheck roleCheck = new RoleCheck(roleName);

        List<FactHandle> handles = new ArrayList<FactHandle>();
        PermissionCheck check = new PermissionCheck(target, action);

        synchronized (securityContext) {
            if (!(target instanceof String) && !(target instanceof Class<?>)) {
                handles.add(securityContext.insert(target));
            } else if (target instanceof Class<?>) {
                // TODO fix
                String componentName = null; //Seam.getComponentName((Class) target);
                target = componentName != null ? componentName : ((Class<?>) target).getName();
            }

            try {
                handles.add(securityContext.insert(check));

                // Check if there are any additional requirements
                securityContext.fireAllRules();
                /*
                if (check.hasRequirements())
                {
                   for (String requirement : check.getRequirements())
                   {
                      // TODO fix
                      Object value = null; // Contexts.lookupInStatefulContexts(requirement);
                      if (value != null)
                      {
                         handles.add (securityContext.insert(value));
                      }
                   }
                }*/

                synchronizeContext();

                handles.add(securityContext.insert(roleCheck));
                handles.add(securityContext.insert(check));

                securityContext.fireAllRules();
            } finally {
                for (FactHandle handle : handles) {
                    securityContext.retract(handle);
                }
            }
        }

        return roleCheck.isGranted();
    }

    public void unAuthenticate(@Observes PostLoggedOutEvent event) {
        if (getSecurityContext() != null) {
            getSecurityContext().dispose();
            setSecurityContext(null);
        }
        init();
    }

    /**
     * Synchronises the state of the security context with that of the subject
     */
    private void synchronizeContext() {
        if (getSecurityContext() != null) {
            getSecurityContext().insert(identity.getUser());

            for (Role role : identity.getRoles()) {
                Iterator<?> iter = getSecurityContext().getObjects(
                        new ClassObjectFilter(Role.class)).iterator();

                boolean found = false;
                while (iter.hasNext()) {
                    Role r = (Role) iter.next();
                    if (r.equals(role)) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    getSecurityContext().insert(role);
                }
            }

            for (Group group : identity.getGroups()) {
                Iterator<?> iter = getSecurityContext().getObjects(
                        new ClassObjectFilter(Group.class)).iterator();

                boolean found = false;
                while (iter.hasNext()) {
                    Group g = (Group) iter.next();
                    if (g.equals(group)) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    getSecurityContext().insert(group);
                }
            }

            Iterator<?> iter = getSecurityContext().getObjects(
                    new ClassObjectFilter(Role.class)).iterator();
            while (iter.hasNext()) {
                Role r = (Role) iter.next();

                if (!identity.hasRole(r.getRoleType().getName(),
                        r.getGroup().getName(), r.getGroup().getGroupType())) {
                    FactHandle fh = getSecurityContext().getFactHandle(r);
                    getSecurityContext().retract(fh);
                }
            }
        }
    }

    public StatefulKnowledgeSession getSecurityContext() {
        return securityContext;
    }

    public void setSecurityContext(StatefulKnowledgeSession securityContext) {
        this.securityContext = securityContext;
    }

    public KnowledgeBase getSecurityRules() {
        return securityRuleLoader.getKnowledgeBase();
    }

    /**
     * Post-authentication event observer
     */
    public void setUserAccountInSecurityContext(@Observes PostAuthenticateEvent event) {
        if (getSecurityContext() != null) {
            getSecurityContext().insert(identity.getUser());
        }
    }
}
