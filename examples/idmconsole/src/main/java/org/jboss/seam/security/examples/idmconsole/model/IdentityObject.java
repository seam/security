package org.jboss.seam.security.examples.idmconsole.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import org.picketlink.idm.spi.model.IdentityObjectType;

/**
 * 
 * @author Shane Bryzak
 */
@Entity
public class IdentityObject implements Serializable
{
   private static final long serialVersionUID = 9158638400039584710L;
   
   private Long id;
   private String name;
   private IdentityObjectType type;
   
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
   public IdentityObjectType getType()
   {
      return type;
   }
   
   public void setIdentityObjectType(IdentityObjectType type)
   {
      this.type = type;
   }
}
