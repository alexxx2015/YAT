package edu.tum.uc.transformer;

import java.util.HashMap;
import java.util.Map;

import edu.tum.uc.jvm.utility.UnsafeUtil;
import edu.tum.uc.tracker.TaintTrackerConfig;

public class RuntimeTracker {
	private static Map<Object,Integer> OBJTAINT = new HashMap<Object,Integer>();
	private static Map<Long,Integer> OBJTAINT2 = new HashMap<Long,Integer>();
	
	public static void addTaint(Object o, int taint){
		long addr = UnsafeUtil.getObjectAddress(o);
		int actualTaint = OBJTAINT2.containsKey(addr) ? OBJTAINT2.get(addr) : TaintTrackerConfig.NULL_TAINT;
		taint |= actualTaint;
		RuntimeTracker.OBJTAINT2.put(addr, taint);
		
//		int actualTaint = OBJTAINT.containsKey(o) ? OBJTAINT.get(o) : TaintTrackerConfig.NULL_TAINT;
//		taint |= actualTaint;
//		RuntimeTracker.OBJTAINT.put(o, taint);
	}
	
//	moves the taint from object o2 to o1, if taint labels exists
	public static void moveTaint(Object o1, Object o2){
		int o1Taint = OBJTAINT.get(o1);
		int o2Taint = OBJTAINT.get(o2);
		int newTaint = o2Taint|o1Taint;
		OBJTAINT.put(o1, newTaint);
	}
	
//	Overwrite object's taint mark
	public static void setTaint(Object o, int taint){
		RuntimeTracker.OBJTAINT.put(o, taint);
	}
	public static void setTaint(int taint, String o){
		RuntimeTracker.OBJTAINT.put(o, taint);
	}
	
//	Reset object's taint mark to empty taint
	public static void newTaint(Object o){
		RuntimeTracker.setTaint(o, TaintTrackerConfig.NULL_TAINT);
	}
	
//	Returns object's taint mark
	public static int getTaint(Object o){
		long addr = UnsafeUtil.getObjectAddress(o);
		if(!OBJTAINT2.containsKey(addr))	
			RuntimeTracker.newTaint(addr);
		return OBJTAINT2.get(addr);
//		if(!OBJTAINT.containsKey(o))	
//			RuntimeTracker.newTaint(o);
//		return OBJTAINT.get(o);
	}
	public static int getTaint(String o){
		if(!OBJTAINT.containsKey(o))	
			RuntimeTracker.newTaint(o);
		return OBJTAINT.get(o);		
	}
}
