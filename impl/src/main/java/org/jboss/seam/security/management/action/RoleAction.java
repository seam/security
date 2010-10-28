package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.List;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.persistence.transaction.Transactional;

@Named
@ConversationScoped
@Transactional
public class RoleAction implements Serializable
{
   private static final long serialVersionUID = -4215849488301658353L;
   
   private String originalRole;
   private String role;
   
   @Inject Conversation conversation;
   
   public void createRole()
   {
      conversation.begin();
   }
   
   public void editRole(String role)
   {
      conversation.begin();
      
      this.originalRole = role;
      this.role = role;
   }
      
   public String save()
   {
      if (role != null && originalRole != null && !role.equals(originalRole))
      {
         //identityManager.deleteRole(originalRole);
      }
      
      /*if (identityManager.roleTypeExists(role))
      {
         return saveExistingRole();
      }
      else
      {
         return saveNewRole();
      }*/
      
      return null;
   }
   
   private String saveNewRole()
   {
      // TODO rewrite
      //boolean success = identityManager.createRole(role);
      
      /*if (success)
      {
         for (String r : groups)
         {
            identityManager.addRoleToGroup(role, r);
         }
         
         conversation.end();
      }*/
      
      return "success";
   }
   
   private String saveExistingRole()
   {
      // FIXME rewrite
      /*List<String> grantedRoles = identityManager.getRoleGroups(role);
      
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
      }*/
               
      conversation.end();
      return "success";
   }
   
   public String getRole()
   {
      return role;
   }
   
   public List<String> getAssignableRoles()
   {
      //List<String> roles = identityManager.getGrantableRoles();
      //roles.remove(role);
      //return roles;
      return null;
   }
   
   public void setRole(String role)
   {
      this.role = role;
   }

}