package org.jboss.seam.security.examples.idmconsole.action;

import javax.enterprise.context.ConversationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceUnit;

import org.jboss.seam.drools.qualifiers.Stateless;
import org.jboss.seam.persistence.SeamManaged;

@Stateless
public class EntityManagerProducer
{
   //@Produces /*@ManagedPersistenceContext @ConversationScoped*/ @RequestScoped 
   //@PersistenceContext(unitName = "idmconsoleDatabase") EntityManager entityManager;
   
//   @Produces @RequestScoped
   //public EntityManager produceEM()
   //{
     // return entityManager;
   //}
      @PersistenceUnit
      @RequestScoped
      @Produces
      @SeamManaged
      EntityManagerFactory emf;   
}
