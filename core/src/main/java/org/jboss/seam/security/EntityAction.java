package org.jboss.seam.security;

/**
 * Actions that may be performed upon entities
 * in JPA or Hibernate.
 * 
 * @author Shane Bryzak
 * 
 */
public enum EntityAction { 
   
   READ, 
   INSERT, 
   UPDATE, 
   DELETE;
   
   @Override
   public String toString()
   {
      return super.name().toLowerCase();
   }
   
}