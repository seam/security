package org.jboss.seam.security.examples.seamspace.action;


import java.util.List;
import java.util.Random;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.examples.seamspace.model.FriendComment;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberBlog;

@RequestScoped
@Named
public class ProfileAction
{
   //@RequestParameter
   private String name;

   @Inject Member selectedMember;
   
   
   @Inject
   private Member authenticatedMember;
   
   //@Out(required = false)
   List<Member> newMembers;
   
   //@Out(required = false)
   List<MemberBlog> memberBlogs;   
   
   @Inject EntityManager entityManager;

   //@Factory("selectedMember")
   public void display()
   {      
      if (name == null && authenticatedMember != null)
      {
         selectedMember = (Member) entityManager.find(Member.class, 
               authenticatedMember.getMemberId());
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
      if (name == null && authenticatedMember != null)
      {
         name = authenticatedMember.getMemberName();
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
