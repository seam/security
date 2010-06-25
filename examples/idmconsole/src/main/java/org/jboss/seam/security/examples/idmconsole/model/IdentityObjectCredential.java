package org.jboss.seam.security.examples.idmconsole.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;

/**
 * Holds credential values
 * 
 * @author Shane Bryzak
 */
@Entity
public class IdentityObjectCredential implements Serializable
{
   private static final long serialVersionUID = 1359292319831314803L;
   
   private Long id;
   private IdentityObject identityObject;
   private IdentityObjectCredentialType type;
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
   
   @ManyToOne @JoinColumn(name = "IDENTITY_OBJECT_ID")
   public IdentityObject getIdentityObject()
   {
      return identityObject;
   }
   
   public void setIdentityObject(IdentityObject identityObject)
   {
      this.identityObject = identityObject;
   }
   
   @ManyToOne @IdentityProperty(PropertyType.TYPE)
   @JoinColumn(name = "CREDENTIAL_TYPE_ID")
   public IdentityObjectCredentialType getType()
   {
      return type;
   }
   
   public void setType(IdentityObjectCredentialType type)
   {
      this.type = type;
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
