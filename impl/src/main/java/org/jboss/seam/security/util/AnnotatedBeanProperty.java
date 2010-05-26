package org.jboss.seam.security.util;

import java.beans.Introspector;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.lang.ExceptionInInitializerError;

/**
 * A convenience class for working with an annotated property (either a field or method) of
 * a JavaBean class.  By providing an isMatch() method in a concrete implementation
 * of this class, annotations may be matched on their attribute values or other
 * conditions.
 *  
 * @author Shane Bryzak
 */
public abstract class AnnotatedBeanProperty<T extends Annotation>
{
   private Field propertyField;
   private Method propertyGetter;
   private Method propertySetter;
   private String name;
   private Type propertyType;
   private T annotation;
   
   private boolean isFieldProperty;
   private boolean set = false;
   
   private Class<?> targetClass;
   private Class<T> annotationClass;
   private boolean scanned = false;
   
   /**
    * Default constructor
    * 
    * @param cls The class to scan for the property
    * @param annotationClass The annotation class to scan for. Specified attribute
    * values may be scanned for by providing an implementation of the isMatch() method. 
    */
   public AnnotatedBeanProperty(Class<?> cls, Class<T> annotationClass)
   {            
      this.targetClass = cls;
      this.annotationClass = annotationClass;
   }   
   
   /**
    * Scans the target class to locate the annotated property
    */
   private void scan()
   {      
      // First check declared fields
      for (Field f : targetClass.getDeclaredFields())
      {
         if (f.isAnnotationPresent(annotationClass) && 
               isMatch(f.getAnnotation(annotationClass))) 
         {
            setupFieldProperty(f);
            this.annotation = f.getAnnotation(annotationClass);            
            set = true;
            return;
         }
      }      
      
      // Then check public fields, in case it's inherited
      for (Field f : targetClass.getFields())
      {
         if (f.isAnnotationPresent(annotationClass) &&
               isMatch(f.getAnnotation(annotationClass))) 
         {
            this.annotation = f.getAnnotation(annotationClass);
            setupFieldProperty(f);
            set = true;
            return;
         }
      }
      
      // Then check public methods (we ignore private methods)
      for (Method m : targetClass.getMethods())
      {
         if (m.isAnnotationPresent(annotationClass) &&
               isMatch(m.getAnnotation(annotationClass)))
         {
            this.annotation = m.getAnnotation(annotationClass);
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
               this.propertyGetter = getGetterMethod(targetClass, this.name);
               this.propertySetter = getSetterMethod(targetClass, this.name);
               this.propertyType = this.propertyGetter.getGenericReturnType();
               isFieldProperty = false;               
               set = true;
            }
            else
            {
               throw new IllegalStateException("Invalid accessor method, must start with 'get' or 'is'.  " +
                     "Method: " + m + " in class: " + targetClass);
            }
         }
      }   
      
      scanned = true;
   }
   
   /**
    * This method must be provided by a concrete implementation of this class. It
    * may be used to scan for an annotation with one or more particular attribute
    * values.  
    * 
    * @param annotation The potential match
    * @return true if the specified annotation is a match
    */
   protected abstract boolean isMatch(T annotation);

   /**
    * This method sets the property value for a specified bean to the specified 
    * value.  The property to be set is either a field or setter method that
    * matches the specified annotation class and returns true for the isMatch() 
    * method.
    * 
    * @param bean The bean containing the property to set
    * @param value The new property value
    * @throws Exception
    */
   public void setValue(Object bean, Object value) throws Exception
   {
      if (!scanned) scan();
      
      if (isFieldProperty)
      {
         setFieldValue(propertyField, bean, value);        
      }
      else
      {
         invokeMethod(propertySetter, bean, value);
      }
   }
    
   /**
    * Returns the property value for the specified bean.  The property to be
    * returned is either a field or getter method that matches the specified
    * annotation class and returns true for the isMatch() method.
    * 
    * @param bean The bean to read the property from
    * @return The property value
    * @throws Exception
    */
   public Object getValue(Object bean) throws Exception
   {
      if (!scanned) scan();
      
      if (isFieldProperty)
      {
         return getFieldValue(propertyField, bean);  
      }
      else
      {
         return invokeMethod(propertyGetter, bean);
      }
   }
   
   /**
    * Returns the name of the property. If the property is a field, then the
    * field name is returned.  Otherwise, if the property is a method, then the
    * name that is returned is the getter method name without the "get" or "is"
    * prefix, and a lower case first letter.
    * 
    * @return The name of the property
    */
   public String getName()
   {
      if (!scanned) scan();      
      return name;
   }
   
   /**
    * Returns the annotation type
    * 
    * @return The annotation type
    */
   public T getAnnotation()
   {
      if (!scanned) scan();
      return annotation;
   }
   
   /**
    * Returns the property type
    * 
    * @return The property type
    */
   public Type getPropertyType()
   {
      if (!scanned) scan();
      return propertyType;
   }
   
   /**
    * Returns true if the property has been successfully located, otherwise
    * returns false.
    * 
    * @return
    */
   public boolean isSet()
   {
      if (!scanned) scan();
      return set;
   }
   
   private void setupFieldProperty(Field propertyField)
   {
      this.propertyField = propertyField;
      isFieldProperty = true;
      this.name = propertyField.getName();
      this.propertyType = propertyField.getGenericType();
   }   
   
   private Object getFieldValue(Field field, Object obj)
   {
      try
      {
         return field.get(obj);
      }
      catch (Exception e)
      {
         if (e instanceof RuntimeException)
         {
            throw (RuntimeException) e;
         }
         else
         {
            throw new IllegalArgumentException(
                  String.format("Exception reading [%s] field from object [%s].",
                        field.getName(), obj), e);
         }         
      }
   }
   
   private void setFieldValue(Field field, Object obj, Object value)
   {
      field.setAccessible(true);
      try
      {
         field.set(obj, value);
      }
      catch (Exception e)
      {
         if (e instanceof RuntimeException)
         {
            throw (RuntimeException) e;
         }
         else
         {
            throw new IllegalArgumentException(
                  String.format("Exception setting [%s] field on object [%s] to value [%s]",
                        field.getName(), obj, value), e);
         }
      }      
   }
   
   private Object invokeMethod(Method method, Object obj, Object... args)
   {
      try
      {
         return method.invoke(obj, args);
      }
      catch (IllegalAccessException ex)
      {
         throw new RuntimeException(buildInvokeMethodErrorMessage(method, obj, args), ex);
      }
      catch (IllegalArgumentException ex)
      {
         throw new RuntimeException(buildInvokeMethodErrorMessage(method, obj, args), ex);
      }
      catch (InvocationTargetException ex)
      {
         throw new RuntimeException(buildInvokeMethodErrorMessage(method, obj, args), ex);
      }
      catch (NullPointerException ex)
      {
         throw new RuntimeException(buildInvokeMethodErrorMessage(method, obj, args), ex);
      }
      catch (ExceptionInInitializerError e)
      {
         throw new RuntimeException(buildInvokeMethodErrorMessage(method, obj, args), e);
      }
   }   
   
   private String buildInvokeMethodErrorMessage(Method method, Object obj, Object... args)
   {
      StringBuilder message = new StringBuilder(String.format(
            "Exception invoking method [%s] on object [%s], using arguments [",
            method.getName(), obj));
      if (args != null) for (int i = 0; i < args.length; i++) message.append((i > 0 ? "," : "") + args[i]);
      message.append("]");
      return message.toString();
   }
   
   private Method getSetterMethod(Class<?> clazz, String name)
   {
      Method[] methods = clazz.getMethods();
      for (Method method: methods)
      {
         String methodName = method.getName();
         if ( methodName.startsWith("set") && method.getParameterTypes().length==1 )
         {
            if ( Introspector.decapitalize( methodName.substring(3) ).equals(name) )
            {
               return method;
            }
         }
      }
      throw new IllegalArgumentException("no such setter method: " + clazz.getName() + '.' + name);
   }
   
   private Method getGetterMethod(Class<?> clazz, String name)
   {
      Method[] methods = clazz.getMethods();
      for (Method method: methods)
      {
         String methodName = method.getName();
         if ( method.getParameterTypes().length==0 )
         {
            if ( methodName.startsWith("get") )
            {
               if ( Introspector.decapitalize( methodName.substring(3) ).equals(name) )
               {
                  return method;
               }
            }
            else if ( methodName.startsWith("is") )
            {
               if ( Introspector.decapitalize( methodName.substring(2) ).equals(name) )
               {
                  return method;
               }
            }
         }
      }
      throw new IllegalArgumentException("no such getter method: " + clazz.getName() + '.' + name);
   }   
}