package org.jboss.seam.security.examples.seamspace.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

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

   public IdentityObjectCredentialType getCredentialType()
   {
      return credentialType;
   }
   
   public void setCredentialType(IdentityObjectCredentialType credentialType)
   {
      this.credentialType = credentialType;
   }
   
   public String getValue()
   {
      return value;
   }
   
   public void setValue(String value)
   {
      this.value = value;
   }
}
