package org.jboss.seam.security;

import java.io.Serializable;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.enterprise.inject.spi.BeanManager;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;

import org.jboss.seam.beans.BeanManagerHelper;
import org.jboss.seam.security.annotations.TokenUsername;
import org.jboss.seam.security.annotations.TokenValue;
import org.jboss.seam.security.management.IdentityManagementException;
import org.jboss.seam.security.util.AnnotatedBeanProperty;

/**
 * A TokenStore implementation, stores tokens inside a database table.
 * 
 * @author Shane Bryzak
 */
@ApplicationScoped
public class JpaTokenStore implements TokenStore, Serializable
{
   private static final long serialVersionUID = -1984227349549914828L;

   private Class<?> tokenEntityClass;
   
   private AnnotatedBeanProperty<TokenUsername> tokenUsernameProperty;
   private AnnotatedBeanProperty<TokenValue> tokenValueProperty;
   
   @Inject BeanManager manager;
   
   @Inject
   public void create()
   {
      tokenUsernameProperty = new AnnotatedBeanProperty<TokenUsername>(tokenEntityClass, TokenUsername.class);
      tokenValueProperty = new AnnotatedBeanProperty<TokenValue>(tokenEntityClass, TokenValue.class);
      
      if (!tokenUsernameProperty.isSet())
      {
         throw new IllegalStateException("Invalid tokenClass " + tokenEntityClass.getName() +
               " - required annotation @TokenUsername not found on any Field or Method.");
      }
      
      if (!tokenValueProperty.isSet())
      {
         throw new IllegalStateException("Invalid tokenClass " + tokenEntityClass.getName() +
               " - required annotation @TokenValue not found on any Field or Method.");
      }
   }
   
   public void createToken(String username, String value)
   {
      if (tokenEntityClass == null)
      {
         throw new IllegalStateException("Could not create token, tokenEntityClass not set");
      }
      
      try
      {
         Object token = tokenEntityClass.newInstance();
         
         tokenUsernameProperty.setValue(token, username);
         tokenValueProperty.setValue(token, value);
         
         lookupEntityManager().persist(token);
      }
      catch (Exception ex)
      {
         if (ex instanceof IdentityManagementException)
         {
            throw (IdentityManagementException) ex;
         }
         else
         {
            throw new IdentityManagementException("Could not create account", ex);
         }
      }
   }
   
   public boolean validateToken(String username, String value)
   {
      return lookupToken(username, value) != null;
   }
   
   public void invalidateToken(String username, String value)
   {
      Object token = lookupToken(username, value);
      if (token != null)
      {
         lookupEntityManager().remove(token);
      }
   }
   
   public void invalidateAll(String username)
   {
      Query query = lookupEntityManager().createQuery(
         "select t from " + tokenEntityClass.getName() + " t where " + tokenUsernameProperty.getName() +
         " = :username")
         .setParameter("username", username);
      
      for (Object token : query.getResultList())
      {
         lookupEntityManager().remove(token);
      }
   }
   
   public Object lookupToken(String username, String value)
   {
      try
      {
         Object token = lookupEntityManager().createQuery(
            "select t from " + tokenEntityClass.getName() + " t where " + tokenUsernameProperty.getName() +
            " = :username and " + tokenValueProperty.getName() + " = :value")
            .setParameter("username", username)
            .setParameter("value", value)
            .getSingleResult();
         
         return token;
      }
      catch (NoResultException ex)
      {
         return null;
      }
   }
   
   public Class<?> getTokenEntityClass()
   {
      return tokenEntityClass;
   }
   
   public void setTokenEntityClass(Class<?> tokenEntityClass)
   {
      this.tokenEntityClass = tokenEntityClass;
   }
   
   private EntityManager lookupEntityManager()
   {
      return BeanManagerHelper.getInstanceByType(manager, EntityManager.class);
   }
}
