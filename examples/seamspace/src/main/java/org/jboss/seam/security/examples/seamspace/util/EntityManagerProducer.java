package org.jboss.seam.security.examples.seamspace.util;

import java.io.Serializable;

import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Produces;
import javax.persistence.EntityManager;

@ConversationScoped
public class EntityManagerProducer implements Serializable
{
   private static final long serialVersionUID = 8654896806568473010L;

   public @Produces EntityManager getEntityManager()
   {
      return null;
   }
}
