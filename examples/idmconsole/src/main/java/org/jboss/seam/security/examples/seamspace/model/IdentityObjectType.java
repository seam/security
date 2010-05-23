package org.jboss.seam.security.examples.seamspace.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * 
 * @author Shane Bryzak
 */
@Entity
public class IdentityObjectType implements Serializable
{
   private static final long serialVersionUID = -3128517252383691733L;
   
   private Long id;
   private String name;
   
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
}
