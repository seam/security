package org.jboss.seam.security.examples.seamspace.action;

import java.io.Serializable;
import java.util.Date;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.Identity;
import org.jboss.seam.security.examples.seamspace.model.FriendComment;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberFriend;

@Named
@ConversationScoped
public class FriendAction implements Serializable
{
   private static final long serialVersionUID = 4565339001481077911L;

   //@RequestParameter("name")
   private String name;
   
   //@Out(required = false)
   private FriendComment friendComment;
   
   //@Out(required = false)
   private MemberFriend friendRequest;
   
   @Inject Member authenticatedMember;
      
   @Inject EntityManager entityManager;
   
   @Inject Conversation conversation;
   
   @Inject Identity identity;
   
   //@Inject StatusMessages messages;
      
   //@Factory("friendComment")
   public void createComment()
   {      
      conversation.begin();
      try
      {
         Member member = (Member) entityManager.createQuery(
         "from Member where memberName = :memberName")
         .setParameter("memberName", name)
         .getSingleResult();
                  
         //Contexts.getMethodContext().set("friends", member.getFriends());
         identity.checkPermission(member, "createFriendComment");

         friendComment = new FriendComment();
         friendComment.setFriend(authenticatedMember);
         friendComment.setMember(member);
      }
      catch (NoResultException ex) 
      { 
         //FacesMessages.instance().add("Member not found.");
      }
   }
   
   public void saveComment()
   {
      friendComment.setCommentDate(new Date());
      entityManager.persist(friendComment);
      conversation.end();
   }
   
   public void createRequest()
   {
      try
      {
         conversation.begin();
         Member member = (Member) entityManager.createQuery(
         "from Member where memberName = :memberName")
         .setParameter("memberName", name)
         .getSingleResult();
                  
         //Contexts.getMethodContext().set("friends", member.getFriends());
         identity.checkPermission(member, "createFriendRequest");

         friendRequest = new MemberFriend();
         friendRequest.setFriend(authenticatedMember);
         friendRequest.setMember(member);
      }
      catch (NoResultException ex) 
      { 
         //FacesMessages.instance().add("Member not found.");
         conversation.end();
      }
   }

   public void saveRequest()
   {
      friendRequest.getMember().getFriends().add(friendRequest);
      entityManager.persist(friendRequest);      
      //FacesMessages.instance().add("Friend request sent");
      conversation.end();
   }
   
}
