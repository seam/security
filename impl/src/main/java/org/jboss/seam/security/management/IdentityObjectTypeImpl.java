package org.jboss.seam.security.management;

import java.io.Serializable;

import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 * Simple implementation of IdentityObjectType
 * 
 * @author Shane Bryzak
 */
public class IdentityObjectTypeImpl implements IdentityObjectType, Serializable
{
   private static final long serialVersionUID = -4364461076493738717L;
   
   private String name;
   
   public IdentityObjectTypeImpl(String name)
   {
      this.name = name;
   }
   
   public String getName()
   {
      return name;
   }
}
