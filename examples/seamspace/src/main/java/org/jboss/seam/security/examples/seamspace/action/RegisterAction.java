package org.jboss.seam.security.examples.seamspace.action;

import java.util.Date;

import javax.enterprise.context.Conversation;
import javax.enterprise.inject.Model;
import javax.inject.Inject;
import javax.persistence.EntityManager;

import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.IdentityImpl;
import org.jboss.seam.security.RunAsOperation;
import org.jboss.seam.security.examples.seamspace.model.Member;
import org.jboss.seam.security.examples.seamspace.model.MemberAccount;
import org.jboss.seam.security.examples.seamspace.model.MemberImage;
import org.jboss.seam.security.management.IdentityManager;

@Model
public class RegisterAction
{
   private Member member;
   
   @Inject EntityManager entityManager;
   
   @Inject Identity identity;
   
   @Inject IdentityImpl identityImpl;
   
   @Inject Credentials credentials;
   
   @Inject IdentityManager identityManager;
   
   @Inject Conversation conversation;
      
   private MemberAccount newAccount;
   
   private String username;   
   
   /**
    * Password confirmation
    */
   private String password;
   private String confirm;   
   
   private String gender;
   
   private byte[] picture;
   private String pictureContentType;
   
   private boolean verified;

   public void start()
   {
      conversation.begin();
      member = new Member();
   }
   
   public void next()
   {
      member.setGender(Member.Gender.valueOf(gender.toLowerCase()));
      
      verified = (confirm != null && confirm.equals(password));
      
      if (!verified)
      {
         //FacesMessages.instance().addToControl("confirmPassword", "Passwords do not match");
      }           
   }
   
   //@Observer(JpaIdentityStore.EVENT_USER_CREATED)
   public void accountCreated(MemberAccount account)
   {
      // The user *may* have been created from the user manager screen. In that
      // case, create a dummy Member record just for the purpose of demonstrating the
      // identity management API
      if (member == null)
      {
         member = new Member();
         member.setMemberName(account.getUsername());
         member.setGender(Member.Gender.male);
         member.setFirstName("John");
         member.setLastName("Doe");
         member.setEmail(account.getUsername() + "@nowhere.com");
         member.setDob(new Date());
         member.setMemberSince(new Date());
         entityManager.persist(member);
      }
      
      account.setMember(member);
      this.newAccount = account;
   }

   public void uploadPicture() 
   {  
      member.setMemberSince(new Date());      
      entityManager.persist(member);      
      
      identityImpl.runAs(new RunAsOperation() {
         public void execute() {
            identityManager.createUser(username, password);
            identityManager.grantRole(username, "user");            
         }         
      }.addRole("admin"));
            
      newAccount.setMember(member);
      newAccount = entityManager.merge(newAccount);

      if (picture != null && picture.length > 0)
      {
         MemberImage img = new MemberImage();
         img.setData(picture);
         img.setMember(member);
         img.setContentType(pictureContentType);
         entityManager.persist(img);
         member.setPicture(img);
         
         member = entityManager.merge(member);
      }
      
      // Login the user
      credentials.setUsername(username);
      credentials.setPassword(password);
      identity.login();
      
      conversation.end();
   }
   
   public Member getMember()
   {
      return member;
   }
   
   public String getUsername()
   {
      return username;
   }
   
   public void setUsername(String username)
   {
      this.username = username;
   }
   
   public String getPassword()
   {
      return password;
   }
   
   public void setPassword(String password)
   {
      this.password = password;
   }
   
   public String getConfirm()
   {
      return confirm;
   }
   
   public void setConfirm(String confirm)
   {
      this.confirm = confirm;
   }
   
   public String getGender()
   {
      return gender;
   }
   
   public void setGender(String gender)
   {
      this.gender = gender;
   }
   
   public void setPicture(byte[] picture)
   {
      this.picture = picture;
   }
   
   public byte[] getPicture()
   {
      return picture;
   }
   
   public String getPictureContentType()
   {
      return pictureContentType;  
   }
   
   public void setPictureContentType(String contentType)
   {
      this.pictureContentType = contentType;
   }
   
   public boolean isVerified()
   {
      return verified;
   }
}
