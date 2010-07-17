package org.jboss.seam.security.examples.seamspace.action;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

import org.jboss.seam.security.crypto.BinTools;
import org.jboss.seam.security.management.PasswordHash;
import org.jboss.seam.security.management.picketlink.JpaIdentityStore;

@Model
public class HashGenerator
{
   @Inject JpaIdentityStore identityStore;
   @Inject PasswordHash hash;
   
   private String password;
   private String passwordHash;
   private String passwordSalt;
   
   public String getPassword()
   {
      return password;
   }
   
   public void setPassword(String password)
   {
      this.password = password;
   }
   
   public String getPasswordHash()
   {
      return passwordHash;
   }
   
   public void setPasswordHash(String passwordHash)
   {
      this.passwordHash = passwordHash;
   }
   
   public String getPasswordSalt()
   {
      return passwordSalt;
   }
   
   public void setPasswordSalt(String passwordSalt)
   {
      this.passwordSalt = passwordSalt;
   }
   
   public void generate()
   {
      byte[] salt;
      
      if (passwordSalt == null || "".equals(passwordSalt.trim()))
      {
         salt = hash.generateRandomSalt();
         passwordSalt = BinTools.bin2hex(salt);
      }
      else
      {
         salt = BinTools.hex2bin(passwordSalt);
      }
      
      passwordHash = identityStore.generatePasswordHash(password, salt);
   }
   
   public String getSql()
   {
      StringBuilder sb = new StringBuilder();
      sb.append("INSERT INTO USER_ACCOUNT (username, password_hash, password_salt) values ('johnsmith', '");
      sb.append(passwordHash);
      sb.append("', '");
      sb.append(passwordSalt);
      sb.append("');");      
      return sb.toString();
   }
}
