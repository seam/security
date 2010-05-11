package org.jboss.seam.security.api;

import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;

/**
 * Seam implementation of the PicketLink Role interface.  Each role is a direct
 * one-to-one mapping between User and Group.  
 * 
 * @author Shane Bryzak
 *
 */
public class Role implements org.picketlink.idm.api.Role 
{
   private Group group;
   private RoleType roleType;
   private User user;
   
   public Role(Group group, RoleType roleType, User user)
   {
      this.group = group;
      this.roleType = roleType;
      this.user = user;
   }
   
   /**
    * Returns the group 
    */
   public Group getGroup()
   {
      return group;
   }

   /**
    * Returns the role type.  (i.e. the name of the role)
    */
   public RoleType getRoleType()
   {
      return roleType;
   }

   /**
    * Returns the user who owns the role
    */
   public User getUser()
   {
      return user;
   }

}
