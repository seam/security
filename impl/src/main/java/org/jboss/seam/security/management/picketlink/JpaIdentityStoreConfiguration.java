package org.jboss.seam.security.management.picketlink;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.picketlink.idm.impl.configuration.metadata.IdentityStoreConfigurationMetaDataImpl;

/**
 * A convenience class for setting JpaIdentityStore configuration options.
 *  
 * @author Shane Bryzak
 */
public class JpaIdentityStoreConfiguration extends IdentityStoreConfiguration
{
   private Class<?> identityClass;
   private Class<?> credentialClass;
   private Class<?> relationshipClass;
   private Class<?> roleNameClass;
   private Class<?> attributeClass;
   
   @Override
   public String getId()
   {
      return (super.getId() == null) ? "jpa" : super.getId();
   }   
   
   /**
    * If the identityStoreClass hasn't been set, then return JpaIdentityStore
    * by default.
    */
   @Override
   public Class<?> getIdentityStoreClass()
   {
      return (super.getIdentityStoreClass() == null) ?
            JpaIdentityStore.class : super.getIdentityStoreClass();
   }
   
   public Class<?> getIdentityClass()
   {
      return identityClass;
   }
   
   public void setIdentityClass(Class<?> identityClass)
   {
      this.identityClass = identityClass;
   }
   
   public Class<?> getCredentialClass()
   {
      return credentialClass;
   }
   
   public void setCredentialClass(Class<?> credentialClass)
   {
      this.credentialClass = credentialClass;
   }

   public Class<?> getRelationshipClass()
   {
      return relationshipClass;
   }
   
   public void setRelationshipClass(Class<?> relationshipClass)
   {
      this.relationshipClass = relationshipClass;
   }

   public Class<?> getRoleNameClass()
   {
      return roleNameClass;
   }
   
   public void setRoleNameClass(Class<?> roleNameClass)
   {
      this.roleNameClass = roleNameClass;
   }

   public Class<?> getAttributeClass()
   {
      return attributeClass;
   }
   
   public void setAttributeClass(Class<?> attributeClass)
   {
      this.attributeClass = attributeClass;
   }
   
   public void doConfigure(IdentityStoreConfigurationMetaDataImpl store)
   {
      Map<String,List<String>> options = new HashMap<String,List<String>>();
      
      if (identityClass != null)
      {
         options.put(JpaIdentityStore.OPTION_IDENTITY_CLASS_NAME, 
            createOptionList(identityClass.getName()));
      }
      
      if (credentialClass != null)
      {
         options.put(JpaIdentityStore.OPTION_CREDENTIAL_CLASS_NAME, 
            createOptionList(credentialClass.getName()));
      }
      
      if (relationshipClass != null)
      {
         options.put(JpaIdentityStore.OPTION_RELATIONSHIP_CLASS_NAME, 
            createOptionList(relationshipClass.getName()));
      }
      
      if (roleNameClass != null)
      {
         options.put(JpaIdentityStore.OPTION_ROLE_NAME_CLASS_NAME, 
            createOptionList(roleNameClass.getName()));
      }
      
      store.setOptions(options);      
   }
      
   private List<String> createOptionList(String... values)
   {
      List<String> vals = new ArrayList<String>();
      for (String v : values) vals.add(v);
      return vals;
   }   
}
