package org.jboss.seam.security.examples.seamspace.action;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.examples.seamspace.model.BlogComment;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberBlog;

@Named
@ConversationScoped
public class BlogAction implements Serializable
{    
   private static final long serialVersionUID = 4537854484817638134L;
   
   private String name;   
   private Integer blogId;
   
   @Inject EntityManager entityManager;
   
   private MemberBlog selectedBlog;
   
   @Inject Member authenticatedMember;
   
   @Inject Conversation conversation;
   
   public MemberBlog getSelectedBlog()
   {
      return selectedBlog;
   }
      
   /**
    * Used to read a single blog entry for a member
    */   
   public void loadBlog()
   {     
      conversation.begin();
      try
      {
         selectedBlog = (MemberBlog) entityManager.createQuery(
           "from MemberBlog b where b.blogId = :blogId and b.member.memberName = :memberName")
           .setParameter("blogId", blogId)
           .setParameter("memberName", name)
           .getSingleResult();
      }
      catch (NoResultException ex) 
      { 
         
      }
   }   
   
   public void createEntry()
   {
      conversation.begin();
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
