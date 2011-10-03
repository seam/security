package org.jboss.seam.security.permission;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.annotations.permission.PermissionProperty;
import org.jboss.seam.security.annotations.permission.PermissionPropertyType;
import org.jboss.seam.security.permission.PermissionMetadata.ActionSet;
import org.jboss.solder.properties.Property;
import org.jboss.solder.properties.query.PropertyCriteria;
import org.jboss.solder.properties.query.PropertyQueries;
import org.picketlink.idm.spi.model.IdentityObject;

/**
 * A permission store implementation that uses JPA as its persistence mechanism.
 *
 * @author Shane Bryzak
 */
@ApplicationScoped
public class JpaPermissionStore implements PermissionStore, Serializable {
    private static final long serialVersionUID = 4764590939669047915L;

    private static final Logger log = Logger.getLogger(JpaPermissionStore.class);

    private class PropertyTypeCriteria implements PropertyCriteria {
        private PermissionPropertyType pt;

        public PropertyTypeCriteria(PermissionPropertyType pt) {
            this.pt = pt;
        }

        public boolean fieldMatches(Field f) {
            return f.isAnnotationPresent(PermissionProperty.class) &&
                    f.getAnnotation(PermissionProperty.class).value().equals(pt);
        }

        public boolean methodMatches(Method m) {
            return m.isAnnotationPresent(PermissionProperty.class) &&
                    m.getAnnotation(PermissionProperty.class).value().equals(pt);
        }
    }

    private boolean enabled;

    private Class<?> identityPermissionClass;

    private Property<Object> identityProperty;
    private Property<?> relationshipTypeProperty;
    private Property<String> relationshipNameProperty;
    private Property<String> resourceProperty;
    private Property<Object> permissionProperty;

    private Map<Integer, String> queryCache = new HashMap<Integer, String>();

    private PermissionMetadata metadata;

    @Inject
    IdentifierPolicy identifierPolicy;
    @Inject
    BeanManager manager;

    @Inject
    Instance<EntityManager> entityManagerInstance;

    @Inject
    public void init() {
        metadata = new PermissionMetadata();

        // TODO see if we can scan for this automatically
        if (identityPermissionClass == null) {
            log.debug("No identityPermissionClass set, JpaPermissionStore will be unavailable.");
            enabled = false;
            return;
        }

        initProperties();
    }

    protected void initProperties() {
        identityProperty = PropertyQueries.createQuery(identityPermissionClass)
                .addCriteria(new PropertyTypeCriteria(PermissionPropertyType.IDENTITY))
                .getFirstResult();

        if (identityProperty == null) {
            throw new RuntimeException("Invalid identityPermissionClass " +
                    identityPermissionClass.getName() +
                    " - required annotation @PermissionProperty(IDENTITY) not found on any field or method.");
        }

        relationshipTypeProperty = PropertyQueries.createQuery(identityPermissionClass)
                .addCriteria(new PropertyTypeCriteria(PermissionPropertyType.RELATIONSHIP_TYPE))
                .getFirstResult();

        if (relationshipTypeProperty == null) {
            throw new RuntimeException("Invalid identityPermissionClass " +
                    identityPermissionClass.getName() +
                    " - required annotation @PermissionProperty(RELATIONSHIP_TYPE) not found on any field or method.");
        }

        relationshipNameProperty = PropertyQueries.<String>createQuery(identityPermissionClass)
                .addCriteria(new PropertyTypeCriteria(PermissionPropertyType.RELATIONSHIP_NAME))
                .getFirstResult();

        if (relationshipNameProperty == null) {
            throw new RuntimeException("Invalid identityPermissionClass " +
                    identityPermissionClass.getName() +
                    " - required annotation @PermissionProperty(RELATIONSHIP_NAME) not found on any field or method.");
        }

        resourceProperty = PropertyQueries.<String>createQuery(identityPermissionClass)
                .addCriteria(new PropertyTypeCriteria(PermissionPropertyType.RESOURCE))
                .getFirstResult();

        if (resourceProperty == null) {
            throw new RuntimeException("Invalid identityPermissionClass " +
                    identityPermissionClass.getName() +
                    " - required annotation @PermissionProperty(RESOURCE) not found on any field or method.");
        }

        permissionProperty = PropertyQueries.createQuery(identityPermissionClass)
                .addCriteria(new PropertyTypeCriteria(PermissionPropertyType.PERMISSION))
                .getFirstResult();

        if (permissionProperty == null) {
            throw new RuntimeException("Invalid identityPermissionClass " +
                    identityPermissionClass.getName() +
                    " - required annotation @PermissionProperty(PERMISSION) not found on any field or method.");
        }

        enabled = true;
    }

    /**
     * Creates a Query that returns a list of permission records for the specified parameters.
     *
     * @param target         The target of the permission, may be null
     * @param targets        A set of permission targets, may be null
     * @param recipient      The permission recipient, may be null
     * @param discrimination A discrimination (either user, role or both), required
     * @return Query The query generated for the provided parameters
     */
    protected Query createPermissionQuery(Object target, Set<?> targets,
                                          IdentityObject identity) {
        if (target != null && targets != null) {
            throw new IllegalArgumentException("Cannot specify both target and targets");
        }

        int queryKey = (target != null) ? 1 : 0;
        queryKey |= (targets != null) ? 2 : 0;
        queryKey |= (identity != null) ? 4 : 0;

        if (!queryCache.containsKey(queryKey)) {
            boolean conditionsAdded = false;

            StringBuilder q = new StringBuilder();
            q.append("select p from ");
            q.append(identityPermissionClass.getName());
            q.append(" p");

            if (target != null) {
                q.append(" where p.");
                q.append(resourceProperty.getName());
                q.append(" = :target");
                conditionsAdded = true;
            }

            if (targets != null) {
                q.append(" where p.");
                q.append(resourceProperty.getName());
                q.append(" in (:targets)");
                conditionsAdded = true;
            }

            if (identity != null) {
                q.append(conditionsAdded ? " and p." : " where p.");
                q.append(identityProperty.getName());
                q.append(" = :identity");
                conditionsAdded = true;
            }

            queryCache.put(queryKey, q.toString());
        }

        Query query = lookupEntityManager().createQuery(queryCache.get(queryKey));

        if (target != null) query.setParameter("target", identifierPolicy.getIdentifier(target));

        if (targets != null) {
            Set<String> identifiers = new HashSet<String>();
            for (Object t : targets) {
                identifiers.add(identifierPolicy.getIdentifier(t));
            }
            query.setParameter("targets", identifiers);
        }

        if (identity != null) query.setParameter("identity", resolveIdentityEntity(identity));

        return query;
    }

    public boolean grantPermission(Permission permission) {
        return updatePermissionActions(permission.getResource(), permission.getIdentity(),
                new String[]{permission.getPermission()}, true);
    }

    public boolean revokePermission(Permission permission) {
        return updatePermissionActions(permission.getResource(), permission.getIdentity(),
                new String[]{permission.getPermission()}, false);
    }

    /**
     * This is where the bulk of the actual work happens.
     *
     * @param target    The target object to update permissions for
     * @param recipient The recipient to update permissions for
     * @param actions   The actions that will be updated
     * @param set       true if the specified actions are to be granted, false if they are to be revoked
     * @return true if the operation is successful
     */
    protected boolean updatePermissionActions(Object resource, IdentityObject identity, String[] actions,
                                              boolean set) {
        try {
            List<?> permissions = createPermissionQuery(resource, null, identity).getResultList();

            if (permissions.isEmpty()) {
                if (!set) return true;

                ActionSet actionSet = metadata.createActionSet(resource.getClass(), null);
                for (String action : actions) {
                    actionSet.add(action);
                }

                Object instance = identityPermissionClass.newInstance();
                resourceProperty.setValue(instance, identifierPolicy.getIdentifier(resource));
                permissionProperty.setValue(instance, actionSet.toString());
                identityProperty.setValue(instance, resolveIdentityEntity(identity));

                lookupEntityManager().persist(instance);
                return true;
            }

            Object instance = permissions.get(0);

            ActionSet actionSet = metadata.createActionSet(resource.getClass(),
                    permissionProperty.getValue(instance).toString());

            for (String action : actions) {
                if (set) {
                    actionSet.add(action);
                } else {
                    actionSet.remove(action);
                }
            }

            if (permissions.size() > 1) {
                // Same as with roles, consolidate the records if there is more than one
                for (Object p : permissions) {
                    actionSet.addMembers(permissionProperty.getValue(p).toString());
                    if (!p.equals(instance)) {
                        lookupEntityManager().remove(p);
                    }
                }
            }

            if (!actionSet.isEmpty()) {
                permissionProperty.setValue(instance, actionSet.toString());
                lookupEntityManager().merge(instance);
            } else {
                // No actions remaining in set, so just remove the record
                lookupEntityManager().remove(instance);
            }

            return true;
        } catch (Exception ex) {
            throw new RuntimeException("Could not grant permission", ex);
        }
    }

    public boolean grantPermissions(List<Permission> permissions) {
        // Target/Recipient/Action map
        Map<Object, Map<IdentityObject, List<Permission>>> groupedPermissions = groupPermissions(permissions);

        for (Object resource : groupedPermissions.keySet()) {
            Map<IdentityObject, List<Permission>> recipientPermissions = groupedPermissions.get(resource);

            for (IdentityObject recipient : recipientPermissions.keySet()) {
                List<Permission> ps = recipientPermissions.get(recipient);
                String[] actions = new String[ps.size()];
                for (int i = 0; i < ps.size(); i++) actions[i] = ps.get(i).getPermission();
                updatePermissionActions(resource, recipient, actions, true);
            }
        }

        return true;
    }

    public boolean revokePermissions(List<Permission> permissions) {
        // Target/Recipient/Action map
        Map<Object, Map<IdentityObject, List<Permission>>> groupedPermissions = groupPermissions(permissions);

        for (Object target : groupedPermissions.keySet()) {
            Map<IdentityObject, List<Permission>> recipientPermissions = groupedPermissions.get(target);

            for (IdentityObject identity : recipientPermissions.keySet()) {
                List<Permission> ps = recipientPermissions.get(identity);
                String[] actions = new String[ps.size()];
                for (int i = 0; i < ps.size(); i++) actions[i] = ps.get(i).getPermission();
                updatePermissionActions(target, identity, actions, false);
            }
        }

        return true;
    }

    /**
     * Groups a list of arbitrary permissions into a more easily-consumed structure
     *
     * @param permissions The list of permissions to group
     * @return
     */
    private Map<Object, Map<IdentityObject, List<Permission>>> groupPermissions(List<Permission> permissions) {
        // Target/Recipient/Action map
        Map<Object, Map<IdentityObject, List<Permission>>> groupedPermissions = new HashMap<Object, Map<IdentityObject, List<Permission>>>();

        for (Permission permission : permissions) {
            if (!groupedPermissions.containsKey(permission.getResource())) {
                groupedPermissions.put(permission.getResource(), new HashMap<IdentityObject, List<Permission>>());
            }

            Map<IdentityObject, List<Permission>> recipientPermissions = groupedPermissions.get(permission.getResource());
            if (!recipientPermissions.containsKey(permission.getIdentity())) {
                List<Permission> perms = new ArrayList<Permission>();
                perms.add(permission);
                recipientPermissions.put(permission.getIdentity(), perms);
            } else {
                recipientPermissions.get(permission.getIdentity()).add(permission);
            }
        }

        return groupedPermissions;
    }

    /**
     * @param recipient
     * @return The entity or name representing the permission recipient
     */
    protected Object resolveIdentityEntity(IdentityObject identity) {
        // TODO implement this method (we already know the identity's entity class)

        return identity.getName();
    }

    /**
     * Returns a list of all user and role permissions for the specified action for all specified target objects
     */
    public List<Permission> listPermissions(Set<Object> targets, String action) {
        // TODO limit the number of targets passed at a single time to 25
        return listPermissions(null, targets, action);
    }

    /**
     * Returns a list of all user and role permissions for a specific permission target and action.
     */
    public List<Permission> listPermissions(Object target, String action) {
        return listPermissions(target, null, action);
    }

    protected List<Permission> listPermissions(Object resource, Set<Object> targets, String action) {
        if (identityPermissionClass == null) return null;

        if (resource != null && targets != null) {
            throw new IllegalArgumentException("Cannot specify both target and targets");
        }

        List<Permission> permissions = new ArrayList<Permission>();

        if (targets != null && targets.isEmpty()) return permissions;

        // First query for user permissions
        Query permissionQuery = targets != null ?
                createPermissionQuery(null, targets, null) :
                createPermissionQuery(resource, null, null);

        List<?> userPermissions = permissionQuery.getResultList();

        Map<String, Object> identifierCache = null;

        if (targets != null) {
            identifierCache = new HashMap<String, Object>();

            for (Object t : targets) {
                identifierCache.put(identifierPolicy.getIdentifier(t), t);
            }
        }

        for (Object permission : userPermissions) {
            ActionSet actionSet = null;

            if (targets != null) {
                //target = identifierCache.get(targetProperty.getValue(permission));
                if (resource != null) {
                    //actionSet = metadata.createActionSet(target.getClass(),
                    // actionProperty.getValue(permission).toString());
                }
            } else {
                //actionSet = metadata.createActionSet(target.getClass(),
                //    actionProperty.getValue(permission).toString());
            }

            if (resource != null && (action == null || (actionSet != null && actionSet.contains(action)))) {
                // FIXME
                IdentityObject identity = null; //lookupPrincipal(principalCache, permission);

                if (action != null) {
                    permissions.add(new Permission(resource, action, identity));
                } else {
                    for (String a : actionSet.members()) {
                        permissions.add(new Permission(resource, a, identity));
                    }
                }
            }
        }

        return permissions;
    }

    public List<Permission> listPermissions(Object target) {
        return listPermissions(target, null);
    }

    public List<String> listAvailableActions(Object target) {
        return metadata.listAllowableActions(target.getClass());
    }

    private EntityManager lookupEntityManager() {
        return entityManagerInstance.get();
    }

    public Class<?> getIdentityPermissionClass() {
        return identityPermissionClass;
    }

    public void setIdentityPermissionClass(Class<?> identityPermissionClass) {
        this.identityPermissionClass = identityPermissionClass;
    }

    public void clearPermissions(Object resource) {
        EntityManager em = lookupEntityManager();
        String identifier = identifierPolicy.getIdentifier(resource);

        em.createQuery(
                "delete from " + identityPermissionClass.getName() + " p where p." +
                        resourceProperty.getName() + " = :resource")
                .setParameter("resource", identifier)
                .executeUpdate();
    }

    public boolean isEnabled() {
        return enabled;
    }
}
