package org.jboss.seam.security.management.action;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.management.IdentityManager;
import org.picketlink.idm.api.Role;
import org.picketlink.idm.impl.api.PasswordCredential;

/**
 * A conversation-scoped component for creating and managing user accounts
 * 
 * @author Shane Bryzak
 */
@Named
@ConversationScoped
public class UserAction implements Serializable
{
   private static final long serialVersionUID = 5820385095080724087L;
   
   private String firstname;
   private String lastname;
   private String username;
   private String password;
   private String confirm;
   private Collection<Role> roles;
   private boolean enabled;
   
   private boolean newUserFlag;
   
   @Inject IdentityManager identityManager;
   @Inject Conversation conversation;
      
   public void createUser()
   {
      conversation.begin();
      roles = new ArrayList<Role>();
      newUserFlag = true;
   }
   
   public void editUser(String username)
   {
      conversation.begin();
      this.username = username;
      roles = identityManager.getUserRoles(username);
      enabled = identityManager.isUserEnabled(username);
      newUserFlag = false;
   }
   
   public void deleteUser(String username)
   {
      identityManager.deleteUser(username);
   }
      
   public String save()
   {
      if (newUserFlag)
      {
         return saveNewUser();
      }
      else
      {
         return saveExistingUser();
      }
   }
   
   private String saveNewUser()
   {
      if (password == null || !password.equals(confirm))
      {
         // TODO - add control message
         //StatusMessages.instance().addToControl("password", "Passwords do not match");
         return "failure";
      }
      
      boolean success = identityManager.createUser(username, new PasswordCredential(password));
      
      if (success)
      {
         /*for (String role : roles)
         {
            identityManager.grantRole(username, role);
         }*/
         
         if (!enabled)
         {
            identityManager.disableUser(username);
         }
         
         conversation.end();
         
         return "success";
      }
      
      return "failure";
   }
   
   private String saveExistingUser()
   {
      // Check if a new password has been entered
      if (password != null && !"".equals(password))
      {
         if (!password.equals(confirm))
         {
            // TODO - add control message
            // StatusMessages.instance().addToControl("password", "Passwords do not match");
            return "failure";
         }
         else
         {
            identityManager.updateCredential(username, new PasswordCredential(password));
         }
      }
      
      Collection<Role> grantedRoles = identityManager.getUserRoles(username);
      
      if (grantedRoles != null)
      {
         for (Role role : grantedRoles)
         {
            if (!roles.contains(role)) identityManager.revokeRole(username, 
                  role.getRoleType().getName(), role.getGroup().getName(),
                  role.getGroup().getGroupType());
         }
      }
      
      for (Role role : roles)
      {
         if (grantedRoles == null || !grantedRoles.contains(role))
         {
            identityManager.grantRole(username, role.getRoleType().getName(), 
                  role.getGroup().getName(), role.getGroup().getGroupType());
         }
      }
      
      if (enabled)
      {
         identityManager.enableUser(username);
      }
      else
      {
         identityManager.disableUser(username);
      }
         
      conversation.end();
      return "success";
   }
   
   public String getFirstname()
   {
      return firstname;
   }
   
   public void setFirstname(String firstname)
   {
      this.firstname = firstname;
   }
   
   public String getLastname()
   {
      return lastname;
   }
   
   public void setLastname(String lastname)
   {
      this.lastname = lastname;
   }
   
   public String getUsername()
   {
      return username;
   }
   
   public void setUsername(String username)
   {
      this.username = username;
   }
   
   public String getPassword()
   {
      return password;
   }
   
   public void setPassword(String password)
   {
      this.password = password;
   }
   
   public String getConfirm()
   {
      return confirm;
   }
   
   public void setConfirm(String confirm)
   {
      this.confirm = confirm;
   }
   
   public Collection<Role> getRoles()
   {
      return roles;
   }
   
   public void setRoles(List<Role> roles)
   {
      this.roles = roles;
   }
   
   public boolean isEnabled()
   {
      return enabled;
   }
   
   public void setEnabled(boolean enabled)
   {
      this.enabled = enabled;
   }
}