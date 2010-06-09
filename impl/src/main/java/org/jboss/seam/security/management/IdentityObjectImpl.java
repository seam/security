package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.common.exception.PolicyValidationException;
import org.picketlink.idm.spi.model.IdentityObject;
import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 * Based implementation of IdentityObject
 * 
 * @author Shane Bryzak
 */
public class IdentityObjectImpl implements IdentityObject, Serializable
{
   private static final long serialVersionUID = -7880202628037808071L;
   
   private String id;
   private String name;
   private IdentityObjectType type;
   
   public IdentityObjectImpl(String id, String name, IdentityObjectType type)
   {
      this.id = id;
      this.name = name;
      this.type = type;
   }

   public String getId()
   {
      return id;
   }

   public IdentityObjectType getIdentityType()
   {
      return type;
   }

   public String getName()
   {
      return name;
   }

   public void validatePolicy() throws PolicyValidationException
   {

   }
}
