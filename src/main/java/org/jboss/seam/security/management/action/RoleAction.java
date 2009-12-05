package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.management.IdentityManager;

@Named
@ConversationScoped
public class RoleAction implements Serializable
{
   private static final long serialVersionUID = -4215849488301658353L;
   
   private String originalRole;
   private String role;
   private List<String> groups;
   
   @Inject IdentityManager identityManager;
   @Inject Conversation conversation;
   
   public void createRole()
   {
      conversation.begin();
      groups = new ArrayList<String>();
   }
   
   public void editRole(String role)
   {
      conversation.begin();
      
      this.originalRole = role;
      this.role = role;
      groups = identityManager.getRoleGroups(role);
   }
      
   public String save()
   {
      if (role != null && originalRole != null && !role.equals(originalRole))
      {
         identityManager.deleteRole(originalRole);
      }
      
      if (identityManager.roleExists(role))
      {
         return saveExistingRole();
      }
      else
      {
         return saveNewRole();
      }
   }
   
   private String saveNewRole()
   {
      boolean success = identityManager.createRole(role);
      
      if (success)
      {
         for (String r : groups)
         {
            identityManager.addRoleToGroup(role, r);
         }
         
         conversation.end();
      }
      
      return "success";
   }
   
   private String saveExistingRole()
   {
      List<String> grantedRoles = identityManager.getRoleGroups(role);
      
      if (grantedRoles != null)
      {
         for (String r : grantedRoles)
         {
            if (!groups.contains(r)) identityManager.removeRoleFromGroup(role, r);
         }
      }
      
      for (String r : groups)
      {
         if (grantedRoles == null || !grantedRoles.contains(r)) identityManager.addRoleToGroup(role, r);
      }
               
      conversation.end();
      return "success";
   }
   
   public String getRole()
   {
      return role;
   }
   
   public List<String> getAssignableRoles()
   {
      List<String> roles = identityManager.listGrantableRoles();
      roles.remove(role);
      return roles;
   }
   
   public void setRole(String role)
   {
      this.role = role;
   }

   public List<String> getGroups()
   {
      return groups;
   }
   
   public void setGroups(List<String> groups)
   {
      this.groups = groups;
   }
}