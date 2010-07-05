package org.jboss.seam.security.examples.idmconsole.action;

import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.jboss.seam.drools.qualifiers.Stateless;

@Stateless
public class EntityManagerProducer
{
   @Produces @ConversationScoped @PersistenceContext(unitName = "idmconsoleDatabase") EntityManager entityManager;
}
