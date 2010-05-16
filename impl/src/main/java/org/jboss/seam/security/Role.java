package org.jboss.seam.security;

import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.RoleType;
import org.picketlink.idm.api.User;

/**
 * Seam implementation of the PicketLink Role interface.  Each role is a direct
 * one-to-one mapping between User and Group.  
 *  
 * @author Shane Bryzak
 */
public class Role implements org.picketlink.idm.api.Role 
{   
   private static final long serialVersionUID = 1187276024036531700L;
   
   private boolean conditional;
   
   private Group group;
   private RoleType roleType;
   private User user;
   
   public Role(Group group, RoleType roleType, User user)
   {
      this.group = group;
      this.roleType = roleType;
      this.user = user;
   }
     
   public boolean isConditional()
   {
      return conditional;
   }

   public Group getGroup()
   {
      return group;
   }

   public RoleType getRoleType()
   {
      return roleType;
   }

   public User getUser()
   {
      return user;
   }
}
