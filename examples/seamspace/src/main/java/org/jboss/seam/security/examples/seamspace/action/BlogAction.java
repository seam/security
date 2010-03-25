package org.jboss.seam.security.examples.seamspace.action;

import java.util.ArrayList;
import java.util.Date;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

@Named("blog")
@ConversationScoped
public class BlogAction
{    
   private String name;   
   private Integer blogId;
   
   @Inject EntityManager entityManager;
   
   @Inject MemberBlog selectedBlog;
   
   @Inject Member authenticatedMember;
   
   @Inject Conversation conversation;
   
   /**
    * Used to read a single blog entry for a member
    */   
   public @Produces @Named("selectedBlog") MemberBlog getBlog()
   {     
      conversation.begin();
      try
      {
         return (MemberBlog) entityManager.createQuery(
           "from MemberBlog b where b.blogId = :blogId and b.member.memberName = :memberName")
           .setParameter("blogId", blogId)
           .setParameter("memberName", name)
           .getSingleResult();
      }
      catch (NoResultException ex) { }
   }   
   
   @Begin
   public void createEntry()
   {
      selectedBlog = new MemberBlog();              
   }
   
   public void saveEntry()
   {
      selectedBlog.setMember(authenticatedMember);
      selectedBlog.setEntryDate(new Date());
      selectedBlog.setComments(new ArrayList<BlogComment>());
      
      entityManager.persist(selectedBlog);
      
      conversation.end();
   }
   
   public String getName()
   {
      return name;
   }
   
   public void setName(String name)
   {
      this.name = name;
   }
   
   public Integer getBlogId()
   {
      return blogId;
   }
   
   public void setBlogId(Integer blogId)
   {
      this.blogId = blogId;
   }
}
