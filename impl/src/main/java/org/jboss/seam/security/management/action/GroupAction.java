package org.jboss.seam.security.management.action;

import java.io.Serializable;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.inject.Named;

import org.jboss.seam.security.GroupImpl;
import org.jboss.seam.persistence.transaction.Transactional;
import org.picketlink.idm.api.Group;
import org.picketlink.idm.api.IdentitySession;
import org.picketlink.idm.common.exception.IdentityException;

/**
 * Action bean for managing groups
 *  
 * @author Shane Bryzak
 */
public @Transactional @Named @ConversationScoped class GroupAction implements Serializable
{
   private static final long serialVersionUID = -1553124158319503903L;
   
   //@Inject Conversation conversation;
   
   //@Inject IdentitySession identitySession;
   
   private String groupName;
   private String groupType;
   
   public void createGroup()
   {
     // conversation.begin();
   }
   
   public void deleteGroup(String name, String groupType) throws IdentityException
   {
      Group group = new GroupImpl(name, groupType);
     // identitySession.getPersistenceManager().removeGroup(group, true);
   }
      
   public String save() throws IdentityException
   {
      //identitySession.getPersistenceManager().createGroup(groupName, groupType);
      //conversation.end();      
      return "success";
   }
}
