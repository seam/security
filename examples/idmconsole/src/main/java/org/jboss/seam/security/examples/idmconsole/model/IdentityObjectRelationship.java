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
 * Contains relationships between identities
 * 
 * @author Shane Bryzak
 */
@Entity
public class IdentityObjectRelationship implements Serializable
{
   private static final long serialVersionUID = -5254503795105571898L;
   
   private Long id;
   private String name;
   private IdentityObjectRelationshipType relationshipType;
   private IdentityObject from;
   private IdentityObject to;
   
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
   
   @ManyToOne @IdentityProperty(PropertyType.TYPE) @JoinColumn(name = "RELATIONSHIP_TYPE_ID")
   public IdentityObjectRelationshipType getRelationshipType()
   {
      return relationshipType;
   }
   
   public void setRelationshipType(IdentityObjectRelationshipType relationshipType)
   {
      this.relationshipType = relationshipType;
   }

   @ManyToOne @IdentityProperty(PropertyType.RELATIONSHIP_FROM) @JoinColumn(name = "FROM_IDENTITY_ID")
   public IdentityObject getFrom()
   {
      return from;
   }
   
   public void setFrom(IdentityObject from)
   {
      this.from = from;
   }

   @ManyToOne @IdentityProperty(PropertyType.RELATIONSHIP_TO) @JoinColumn(name = "TO_IDENTITY_ID")
   public IdentityObject getTo()
   {
      return to;
   }
   
   public void setTo(IdentityObject to)
   {
      this.to = to;
   }
}
