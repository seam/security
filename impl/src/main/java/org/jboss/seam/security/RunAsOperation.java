package org.jboss.seam.security;

import org.picketlink.idm.api.User;

/**
 * Defines a security operation that can be executed within a particular
 * security context.
 *
 * @author Shane Bryzak
 */
public abstract class RunAsOperation {
    private User user;

    private boolean systemOp = false;

    public RunAsOperation() {
    }

    /**
     * A system operation allows any security checks to pass
     *
     * @param systemOp
     */
    public RunAsOperation(boolean systemOp) {
        this();
        this.systemOp = systemOp;
    }

    public abstract void execute();

    public User getUser() {
        return user;
    }

    public RunAsOperation addRole(String role) {
        // FIXME this all has to change

        /*for ( Group sg : getSubject().getPrincipals(Group.class) )
        {
           if ( IdentityImpl.ROLES_GROUP.equals( sg.getName() ) )
           {
              //sg.addMember(new SimplePrincipal(role));
              break;
           }
        }*/

        // TODO fix this
        //SimpleGroup roleGroup = new SimpleGroup(IdentityImpl.ROLES_GROUP);
        //roleGroup.addMember(new SimplePrincipal(role));
        //getSubject().getPrincipals().add(roleGroup);

        return this;
    }

    public boolean isSystemOperation() {
        return systemOp;
    }
}
