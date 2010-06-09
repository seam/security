package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectRelationship;
import org.picketlink.idm.spi.model.IdentityObjectRelationshipType;

/**
 * 
 * @author Shane Bryzak
 */
public class IdentityObjectRelationshipImpl implements IdentityObjectRelationship, Serializable
{
   private static final long serialVersionUID = 487517126125658201L;
   
   private IdentityObject fromIdentityObject;
   private IdentityObject toIdentityObject;
   private String name;
   private IdentityObjectRelationshipType type;
   
   public IdentityObjectRelationshipImpl(IdentityObject fromIdentityObject,
         IdentityObject toIdentityObject, String name, 
         IdentityObjectRelationshipType type)
   {
      this.fromIdentityObject = fromIdentityObject;
      this.toIdentityObject = toIdentityObject;
      this.name = name;
      this.type = type;
   }

   public IdentityObject getFromIdentityObject()
   {
      return fromIdentityObject;
   }

   public IdentityObject getToIdentityObject()
   {
      return toIdentityObject;
   }   

   public String getName()
   {
      return name;
   }

   public IdentityObjectRelationshipType getType()
   {
      return type;
   }
}
