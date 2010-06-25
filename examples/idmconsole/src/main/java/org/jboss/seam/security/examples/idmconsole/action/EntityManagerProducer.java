package org.jboss.seam.security.examples.idmconsole.action;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

public class EntityManagerProducer
{
   @PersistenceContext EntityManager entityManager;
   
   public @Produces @RequestScoped EntityManager produceEntityManager()
   {
      return entityManager;
   }
}
