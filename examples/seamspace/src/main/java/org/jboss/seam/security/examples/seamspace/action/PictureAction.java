package org.jboss.seam.security.examples.seamspace.action;


import javax.enterprise.inject.Model;
import javax.persistence.EntityManager;

@Model
public class PictureAction
{
   private MemberImage memberImage;
   
   @In(required = false)
   private Member authenticatedMember;
   
   @In EntityManager entityManager;
   
   @Begin
   public void uploadPicture()
   {
      memberImage = new MemberImage();
   }
   
   public void savePicture()
   {
      memberImage.setMember(entityManager.find(Member.class, authenticatedMember.getMemberId()));
      entityManager.persist(memberImage);
      Conversation.instance().end();
   }

   public MemberImage getMemberImage()
   {
      return memberImage;
   }
}
