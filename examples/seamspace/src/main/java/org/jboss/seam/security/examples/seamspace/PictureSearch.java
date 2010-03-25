package org.jboss.seam.security.examples.seamspace;


import java.io.Serializable;
import java.util.List;

import javax.enterprise.context.RequestScoped;
import javax.inject.Named;
import javax.persistence.EntityManager;

import org.jboss.seam.security.Identity;

@RequestScoped
@Named
public class PictureSearch implements Serializable
{
   private static final long serialVersionUID = -1868188969326866331L;
   
   private String memberName;
   
   @In
   private EntityManager entityManager;
   
   @Out(required = false)
   private List<MemberImage> memberImages;
   
   @RequestParameter
   private Integer imageId;
   
   public String getMemberName()
   {
      return memberName;
   }

   public void setMemberName(String memberName)
   {
      this.memberName = memberName;
   }
   
   public void delete(@Delete MemberImage image)
   {
      entityManager.remove(image);
   }
   
   public MemberImage lookupImage()
   {
      return entityManager.find(MemberImage.class, imageId);
   }
   
   @SuppressWarnings("unchecked")
   public void loadMemberPictures()
   {
      memberImages = (List<MemberImage>) entityManager.createQuery(
            "select i from MemberImage i where i.member.memberName = :name and not i = i.member.picture")
            .setParameter("name", memberName)
            .getResultList();      
      Identity.instance().filterByPermission(memberImages, "view");
   }
}
