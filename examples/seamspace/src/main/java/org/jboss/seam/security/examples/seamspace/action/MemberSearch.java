package org.jboss.seam.security.examples.seamspace.action;

import java.util.List;
import java.util.Random;

import javax.enterprise.inject.Model;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.jboss.seam.security.examples.seamspace.model.Member;

@Model
public class MemberSearch
{
   @Inject EntityManager entityManager;
   
   private List<Member> newMembers;
   
   /**
    * Returns a random selection of 3 members out of the latest 10 new members
    * 
    * @return A List<Member> containing 3 random members
    */
   @SuppressWarnings("unchecked")
   public List<Member> getNewMembers()
   {
      if (newMembers == null)
      {
         newMembers = entityManager.createQuery(
               "from Member order by memberSince desc")
               .setMaxResults(10)
               .getResultList();
         
         // Randomly select 3 of the latest 10 members
         Random rnd = new Random(System.currentTimeMillis());
         while (newMembers.size() > 3)
         {
            newMembers.remove(rnd.nextInt(newMembers.size()));
         }
      }
      return newMembers;
   }
}
