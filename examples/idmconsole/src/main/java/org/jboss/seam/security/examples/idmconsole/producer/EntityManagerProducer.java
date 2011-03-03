package org.jboss.seam.security.examples.idmconsole.producer;

import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceUnit;

import org.jboss.seam.persistence.SeamManaged;

/**
 * 
 * @author Shane Bryzak
 *
 */
public class EntityManagerProducer
{
   @Produces
   @SeamManaged
   @ConversationScoped
   @PersistenceUnit
   EntityManagerFactory emf;
}
