package org.jboss.seam.security.examples.idmconsole.producer;

import javax.annotation.Resource;
import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;

import org.jboss.seam.persistence.SeamManaged;

public class EntityManagerProducer
{
 //  @PersistenceUnit @Resource(mappedName="java:/idmconsoleEntityManagerFactory")
//   private EntityManagerFactory emf;
      
   /*@Produces
   @SeamManaged
   @ConversationScoped
   public EntityManagerFactory createEmf()
   {
      return emf;
   } */
   
   @SeamManaged
   @Produces
   @PersistenceUnit
   @ConversationScoped
   EntityManagerFactory emf;
}
