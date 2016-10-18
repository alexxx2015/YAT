package edu.tum.uc.transformer;

import java.lang.reflect.Method;

public class Logger {
	
	public static void log(int i, String text){
		System.out.println(text+"; TAINT: "+Integer.toBinaryString(i)+" , "+i);
	}
	
	public static void log(Object o){
		System.out.println("LOGGER: "+o.getClass().getName());
	}
	
	public static void log(Method m){
		System.out.println("LOGGER: "+m.getName()+", "+m.getReturnType());
		for(Class c : m.getParameterTypes()){
			System.out.println(m.getName()+": "+c.getName());
		}
	}

}
