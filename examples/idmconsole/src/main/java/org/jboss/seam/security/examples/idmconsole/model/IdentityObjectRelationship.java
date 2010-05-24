package org.jboss.seam.security.examples.idmconsole.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import org.jboss.seam.security.annotations.management.IdentityProperty;
import org.jboss.seam.security.annotations.management.PropertyType;

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
   
   @IdentityProperty(PropertyType.NAME)
   public String getName()
   {
      return name;
   }
   
   public void setName(String name)
   {
      this.name = name;
   }
   
   @ManyToOne @IdentityProperty(PropertyType.TYPE)
   public IdentityObjectRelationshipType getRelationshipType()
   {
      return relationshipType;
   }
   
   public void setRelationshipType(IdentityObjectRelationshipType relationshipType)
   {
      this.relationshipType = relationshipType;
   }
   
   @ManyToOne @IdentityProperty(PropertyType.RELATIONSHIP_FROM)
   public IdentityObject getFromObject()
   {
      return fromObject;
   }
   
   public void setFromObject(IdentityObject fromObject)
   {
      this.fromObject = fromObject;
   }
   
   @ManyToOne @IdentityProperty(PropertyType.RELATIONSHIP_TO)
   public IdentityObject getToObject()
   {
      return toObject;
   }
   
   public void setToObject(IdentityObject toObject)
   {
      this.toObject = toObject;
   }
}
