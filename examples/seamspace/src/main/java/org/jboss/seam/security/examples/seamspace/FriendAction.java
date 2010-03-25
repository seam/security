package org.jboss.seam.security.examples.seamspace;

import java.io.Serializable;
import java.util.Date;

import javax.ejb.Remove;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.seam.security.Identity;

@Named
@ConversationScoped
public class FriendAction implements Serializable
{
   private static final long serialVersionUID = 4565339001481077911L;

   @RequestParameter("name")
   private String name;
   
   @Out(required = false)
   private FriendComment friendComment;
   
   @Out(required = false)
   private MemberFriend friendRequest;
   
   @In(required = false)
   private Member authenticatedMember;
      
   @In
   private EntityManager entityManager;
      
   @Factory("friendComment") @Begin
   public void createComment()
   {      
      try
      {
         Member member = (Member) entityManager.createQuery(
         "from Member where memberName = :memberName")
         .setParameter("memberName", name)
         .getSingleResult();
                  
         Contexts.getMethodContext().set("friends", member.getFriends());
         Identity.instance().checkPermission(member, "createFriendComment");

         friendComment = new FriendComment();
         friendComment.setFriend(authenticatedMember);
         friendComment.setMember(member);
      }
      catch (NoResultException ex) 
      { 
         FacesMessages.instance().add("Member not found.");
      }
   }
   
   @End
   public void saveComment()
   {
      friendComment.setCommentDate(new Date());
      entityManager.persist(friendComment);
   }
   
   @Begin
   public void createRequest()
   {
      try
      {
         Member member = (Member) entityManager.createQuery(
         "from Member where memberName = :memberName")
         .setParameter("memberName", name)
         .getSingleResult();
                  
         Contexts.getMethodContext().set("friends", member.getFriends());
         Identity.instance().checkPermission(member, "createFriendRequest");

         friendRequest = new MemberFriend();
         friendRequest.setFriend(authenticatedMember);
         friendRequest.setMember(member);
      }
      catch (NoResultException ex) 
      { 
         FacesMessages.instance().add("Member not found.");
      }
   }

   @End
   public void saveRequest()
   {
      friendRequest.getMember().getFriends().add(friendRequest);
      entityManager.persist(friendRequest);      
      FacesMessages.instance().add("Friend request sent");      
   }
   
   @Remove @Destroy
   public void destroy() { }    
}
