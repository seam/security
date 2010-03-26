package org.jboss.seam.security.examples.seamspace.action;

import java.util.Date;

import javax.enterprise.context.Conversation;
import javax.enterprise.inject.Model;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.jboss.seam.security.annotations.Insert;
import org.jboss.seam.security.examples.seamspace.model.BlogComment;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberBlog;

@Model
//@Transactional
public class CommentAction 
{
   @Inject EntityManager entityManager;
   
   private BlogComment comment;     
   
   @Inject Member authenticatedMember;
   
   /*@Inject */MemberBlog selectedBlog;
   
   @Inject Conversation conversation;
   
   @Insert(BlogComment.class) 
   public void createComment()
   {            
      conversation.begin();
      comment = new BlogComment();
      comment.setCommentor(authenticatedMember);              
      comment.setBlog(selectedBlog);
   }
   
   public void saveComment()
   {      
      comment.setCommentDate(new Date());
      entityManager.persist(comment);
            
      entityManager.refresh(selectedBlog);
      
      conversation.end();
   }    
   
   public BlogComment getComment()
   {
      return comment;
   }
}
