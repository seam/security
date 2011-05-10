package org.jboss.seam.security.permission;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.seam.security.annotations.permission.Permissions;

/**
 * Permission actions can either be persisted as a comma-separated list of values, or as a
 * bit-masked numerical value where certain bits represent specific actions for that class. This
 * is a helper class that handles the conversion automatically and presents a unified API for
 * dealing with these persistent actions.
 *
 * @author Shane Bryzak
 */
public class PermissionMetadata {
    private Map<Class<?>, Boolean> usesActionMask = new HashMap<Class<?>, Boolean>();
    private Map<Class<?>, Map<String, Long>> classActions = new HashMap<Class<?>, Map<String, Long>>();

    private synchronized void initClassActions(Class<?> cls) {
        if (!classActions.containsKey(cls)) {
            Map<String, Long> actions = new HashMap<String, Long>();

            boolean useMask = false;

            Permissions p = (Permissions) cls.getAnnotation(Permissions.class);
            if (p != null) {
                org.jboss.seam.security.annotations.permission.Permission[] permissions = p.value();
                if (permissions != null) {
                    for (org.jboss.seam.security.annotations.permission.Permission permission : permissions) {
                        actions.put(permission.action(), permission.mask());

                        if (permission.mask() != 0) {
                            useMask = true;
                        }
                    }
                }
            }

            // Validate that all actions have a proper mask
            if (useMask) {
                Set<Long> masks = new HashSet<Long>();

                for (String action : actions.keySet()) {
                    Long mask = actions.get(action);
                    if (masks.contains(mask)) {
                        throw new IllegalArgumentException("Class " + cls.getName() +
                                " defines a duplicate mask for permission action [" + action + "]");
                    }

                    if (mask == 0) {
                        throw new IllegalArgumentException("Class " + cls.getName() +
                                " must define a valid mask value for action [" + action + "]");
                    }

                    if ((mask & (mask - 1)) != 0) {
                        throw new IllegalArgumentException("Class " + cls.getName() +
                                " must define a mask value that is a power of 2 for action [" + action + "]");
                    }

                    masks.add(mask);
                }
            }

            usesActionMask.put(cls, useMask);
            classActions.put(cls, actions);
        }
    }

    protected class ActionSet {
        private Set<String> members = new HashSet<String>();
        private Class<?> targetClass;

        public ActionSet(Class<?> targetClass, String members) {
            this.targetClass = targetClass;
            addMembers(members);
        }

        public void addMembers(String members) {
            if (members == null) return;

            if (usesActionMask.get(targetClass)) {
                // bit mask-based actions
                long vals = Long.valueOf(members);

                Map<String, Long> actions = classActions.get(targetClass);
                for (String action : actions.keySet()) {
                    long mask = actions.get(action).longValue();
                    if ((vals & mask) != 0) {
                        this.members.add(action);
                    }
                }
            } else {
                // comma-separated string based actions
                String[] actions = members.split(",");
                for (String action : actions) {
                    this.members.add(action);
                }
            }
        }

        public boolean contains(String action) {
            return members.contains(action);
        }

        public ActionSet add(String action) {
            members.add(action);
            return this;
        }

        public ActionSet remove(String action) {
            members.remove(action);
            return this;
        }

        public Set<String> members() {
            return members;
        }

        public boolean isEmpty() {
            return members.isEmpty();
        }

        @Override
        public String toString() {
            if (usesActionMask.get(targetClass)) {
                Map<String, Long> actions = classActions.get(targetClass);
                long mask = 0;

                for (String member : members) {
                    mask |= actions.get(member).longValue();
                }

                return "" + mask;
            } else {
                StringBuilder sb = new StringBuilder();
                for (String member : members) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(member);
                }
                return sb.toString();
            }
        }
    }

    public ActionSet createActionSet(Class<?> targetClass, String members) {
        if (!classActions.containsKey(targetClass)) initClassActions(targetClass);

        return new ActionSet(targetClass, members);
    }

    public List<String> listAllowableActions(Class<?> targetClass) {
        if (!classActions.containsKey(targetClass)) initClassActions(targetClass);

        List<String> actions = new ArrayList<String>();
        for (String action : classActions.get(targetClass).keySet()) {
            actions.add(action);
        }

        return actions;
    }
}
