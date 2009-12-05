package org.jboss.seam.security.permission.action;

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.management.IdentityManager;
import org.jboss.seam.security.permission.Permission;
import org.jboss.seam.security.permission.PermissionManager;

@Named
@ConversationScoped
public class PermissionSearch implements Serializable
{
   private static final long serialVersionUID = 2802038930768758665L;

   private Map<Principal,List<Permission>> groupedPermissions = new HashMap<Principal,List<Permission>>();
 
   
   //@DataModel(scope = ConversationScoped.class)
   List<Principal> recipients;
   
   //@DataModelSelection
   Principal selectedRecipient;
   
   @Inject IdentityManager identityManager;   
   @Inject PermissionManager permissionManager;   
   @Inject Conversation conversation;
   
   private Object target;
   
   public void search(Object target)
   {
      conversation.begin();
      this.target = target;
   }
   
   public void refresh()
   {
      List<Permission> permissions = permissionManager.listPermissions(target);
      groupedPermissions.clear();
      
      for (Permission permission : permissions)
      {
         List<Permission> recipientPermissions = null;
         
         if (!groupedPermissions.containsKey(permission.getRecipient()))
         {
            recipientPermissions = new ArrayList<Permission>();
            groupedPermissions.put(permission.getRecipient(), recipientPermissions);
         }
         else
         {
            recipientPermissions = groupedPermissions.get(permission.getRecipient());
         }
         
         recipientPermissions.add(permission);
      }
      
      recipients = new ArrayList<Principal>(groupedPermissions.keySet());
   }
   
   public String getActions(Principal recipient)
   {
      StringBuilder sb = new StringBuilder();
      
      for (Permission permission : groupedPermissions.get(recipient))
      {
         if (sb.length() > 0) sb.append(", ");
         sb.append(permission.getAction());
      }
      
      return sb.toString();
   }
   
   public Object getTarget()
   {
      return target;
   }
   
   public void revokeSelected()
   {
      permissionManager.revokePermissions(getSelectedPermissions());
      refresh();
   }
   
   public Principal getSelectedRecipient()
   {
      return selectedRecipient;
   }
   
   public List<Permission> getSelectedPermissions()
   {
      return groupedPermissions.get(selectedRecipient);
   }
}
