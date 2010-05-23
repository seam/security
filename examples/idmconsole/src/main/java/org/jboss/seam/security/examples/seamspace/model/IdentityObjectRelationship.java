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
public class IdentityObjectRelationship implements Serializable
{
   private static final long serialVersionUID = -677485940440910431L;
   
   private Long id;
   private String name;
   private IdentityObjectRelationshipType relationshipType;
   private IdentityObject fromObject;
   private IdentityObject toObject;
   
   @Id @GeneratedValue
   public Long getId()
   {
      return id;
   }
   
   public void setId(Long id)
   {
      this.id = id;
   }
   
   public String getName()
   {
      return name;
   }
   
   public void setName(String name)
   {
      this.name = name;
   }
   
   @ManyToOne
   public IdentityObjectRelationshipType getRelationshipType()
   {
      return relationshipType;
   }
   
   public void setRelationshipType(IdentityObjectRelationshipType relationshipType)
   {
      this.relationshipType = relationshipType;
   }
   
   @ManyToOne
   public IdentityObject getFromObject()
   {
      return fromObject;
   }
   
   public void setFromObject(IdentityObject fromObject)
   {
      this.fromObject = fromObject;
   }
   
   @ManyToOne
   public IdentityObject getToObject()
   {
      return toObject;
   }
   
   public void setToObject(IdentityObject toObject)
   {
      this.toObject = toObject;
   }
}
