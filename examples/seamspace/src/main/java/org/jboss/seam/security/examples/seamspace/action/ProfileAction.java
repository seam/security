package org.jboss.seam.security.examples.seamspace.action;


import java.util.List;

import javax.enterprise.inject.Model;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.examples.seamspace.model.FriendComment;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberAccount;
import org.jboss.seam.security.examples.seamspace.model.MemberBlog;
import org.jboss.seam.security.examples.seamspace.util.Authenticated;

@Model
public class ProfileAction
{
   private String name;

   private Member selectedMember;   
      
   private @Inject @Authenticated MemberAccount authenticatedAccount;
   
   //@Out(required = false)
   List<Member> newMembers;
   
   //@Out(required = false)
   List<MemberBlog> memberBlogs;   
   
   @Inject EntityManager entityManager;

   public Member getSelectedMember()
   {   
      if (selectedMember == null)
      {
         if (name == null && authenticatedAccount != null)
         {
            selectedMember = (Member) entityManager.find(Member.class, 
                  authenticatedAccount.getMember().getMemberId());
         }
         else if (name != null)
         {
            try
            {
               selectedMember = (Member) entityManager.createQuery(
               "from Member where memberName = :memberName")
               .setParameter("memberName", name)
               .getSingleResult(); 
            }
            catch (NoResultException ex) { }
         }
      }
      
      return selectedMember;
   }
   
   /**
    * Returns the 5 latest blog entries for a member
    */
   @SuppressWarnings("unchecked")
   public List<MemberBlog> getLatestBlogs()
   {
      return entityManager.createQuery(
           "from MemberBlog b where b.member = :member order by b.entryDate desc")
           .setParameter("member", selectedMember)
           .setMaxResults(5)
           .getResultList();
   }

   /**
    * Used to read all blog entries for a member
    */
   @SuppressWarnings("unchecked")
   //@Factory("memberBlogs")
   public void getMemberBlogs()
   {
      if (name == null && authenticatedAccount != null)
      {
         name = authenticatedAccount.getMember().getMemberName();
      }      
      
      memberBlogs = entityManager.createQuery(
            "from MemberBlog b where b.member.memberName = :memberName order by b.entryDate desc")
            .setParameter("memberName", name)
            .getResultList();
   }   
      
   @SuppressWarnings("unchecked")
   public List<Member> getFriends()
   {
      return entityManager.createQuery(
            "select f.friend from MemberFriend f where f.member = :member and authorized = true")
            .setParameter("member", selectedMember)
            .getResultList();
   }
   
   @SuppressWarnings("unchecked")
   public List<FriendComment> getFriendComments()
   {
      return entityManager.createQuery(
            "from FriendComment c where c.member = :member order by commentDate desc")
            .setParameter("member", selectedMember)
            .getResultList();
   }  
}
