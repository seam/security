package org.jboss.seam.security.util;

import java.beans.Introspector;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class TypedBeanProperty
{
   private Field propertyField;
   private Method propertyGetter;
   private Method propertySetter;
   
   private String name;
   
   private boolean isFieldProperty;
   private boolean set = false;
   
   public TypedBeanProperty(Class<?> cls, Class type)
   {      
      // First check declared fields
      for (Field f : cls.getDeclaredFields())
      {
         if (f.getGenericType().equals(type)) 
         {
            setupFieldProperty(f);           
            set = true;
            return;
         }
      }      
      
      // Then check public fields, in case it's inherited
      for (Field f : cls.getFields())
      {
         if (f.getGenericType().equals(type)) 
         {
            setupFieldProperty(f);
            set = true;
            return;
         }
      }
      
      // Then check public methods (we ignore private methods)
      for (Method m : cls.getMethods())
      {
         if (m.getGenericReturnType().equals(type))
         {
            String methodName = m.getName();
            
            if ( m.getName().startsWith("get") )
            {
               this.name = Introspector.decapitalize( m.getName().substring(3) );
            }
            else if ( methodName.startsWith("is") )
            {
               this.name = Introspector.decapitalize( m.getName().substring(2) );
            }            
            
            if (this.name != null)
            {
               this.propertyGetter = Reflections.getGetterMethod(cls, this.name);
               this.propertySetter = Reflections.getSetterMethod(cls, this.name);
               isFieldProperty = false;               
               set = true;
            }
            else
            {
               throw new IllegalStateException("Invalid accessor method, must start with 'get' or 'is'.  " +
                     "Method: " + m + " in class: " + cls);
            }
         }
      }      
   }
   
   private void setupFieldProperty(Field propertyField)
   {
      this.propertyField = propertyField;
      isFieldProperty = true;
      this.name = propertyField.getName();
   }   
   
   public void setValue(Object bean, Object value)
   {
      if (isFieldProperty)
      {
         Reflections.setAndWrap(propertyField, bean, value);         
      }
      else
      {
         Reflections.invokeAndWrap(propertySetter, bean, value);
      }
   }
   
   public Object getValue(Object bean)
   {
      if (isFieldProperty)
      {
         return Reflections.getAndWrap(propertyField, bean);  
      }
      else
      {
         return Reflections.invokeAndWrap(propertyGetter, bean);
      }
   }   
   
   public String getName()
   {
      return name;
   }
   
   public boolean isSet()
   {
      return set;
   }
}