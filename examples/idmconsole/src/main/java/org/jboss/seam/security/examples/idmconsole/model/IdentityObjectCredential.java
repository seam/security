package org.jboss.seam.security.examples.idmconsole.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import org.jboss.seam.security.annotations.management.IdentityEntityType;
import org.jboss.seam.security.annotations.management.IdentityEntityValue;
import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;

/**
 * 
 * @author Shane Bryzak
 */
@Entity
public class IdentityObjectCredential implements Serializable
{
   private static final long serialVersionUID = -3322215745174559505L;
   
   private Long id;
   private IdentityObject identityObject;
   private IdentityObjectCredentialType credentialType;
   private String value;
   
   @Id @GeneratedValue
   public Long getId()
   {
      return id;
   }
   
   public void setId(Long id)
   {
      this.id = id;
   }
   
   @ManyToOne
   public IdentityObject getIdentityObject()
   {
      return identityObject;
   }
   
   public void setIdentityObject(IdentityObject identityObject)
   {
      this.identityObject = identityObject;
   }

   @ManyToOne @IdentityProperty(PropertyType.TYPE)
   public IdentityObjectCredentialType getCredentialType()
   {
      return credentialType;
   }
   
   public void setCredentialType(IdentityObjectCredentialType credentialType)
   {
      this.credentialType = credentialType;
   }
   
   @IdentityProperty(PropertyType.VALUE)
   public String getValue()
   {
      return value;
   }
   
   public void setValue(String value)
   {
      this.value = value;
   }
}
