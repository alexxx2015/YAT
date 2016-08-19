package edu.tum.uc.transformer.taint;

import edu.tum.uc.tracker.TaintTrackerConfig;

public class TaintWrapper<V,T> {

	public T taint;	
	public V value;
	
	public TaintWrapper(V value, T taint){
		this.value = value;
		this.taint = taint;
	}
	
	public T getTaint(){
		return this.taint;
	}
	
	public V getValue(){
		return this.value;
	}

	public static TaintWrapper<Boolean,Integer> getWrapper(Boolean i, int taint){
		return new TaintWrapper<Boolean,Integer>(i,taint);
	}
	public static TaintWrapper<Byte,Integer> getWrapper(Byte i, int taint){
		return new TaintWrapper<Byte,Integer>(i,taint);
	}
	public static TaintWrapper<Character,Integer> getWrapper(Character i, int taint){
		return new TaintWrapper<Character,Integer>(i,taint);
	}
	public static TaintWrapper<Short,Integer> getWrapper(Short i, int taint){
		return new TaintWrapper<Short,Integer>(i,taint);
	}
	public static TaintWrapper<Integer,Integer> getWrapper(int i, int taint){
		return new TaintWrapper<Integer,Integer>(i,taint);
	}
	public static TaintWrapper<Long,Integer> getWrapper(long i, int taint){
		return new TaintWrapper<Long,Integer>(i,taint);
	}
	public static TaintWrapper<Float,Integer> getWrapper(float i, int taint){
		return new TaintWrapper<Float,Integer>(i,taint);
	}
	public static TaintWrapper<Double,Integer> getWrapper(double i, int taint){
		return new TaintWrapper<Double,Integer>(i,taint);
	}	
	public static TaintWrapper<Boolean,Integer> getWrapper(boolean i, int taint){
		return new TaintWrapper<Boolean,Integer>(i,taint);
	}
	public static TaintWrapper<String,Integer> getWrapper(String s, int taint){
		return new TaintWrapper<String,Integer>(s,taint);
	}	

	public static TaintWrapper<Boolean[],Integer[]> getWrapper(Boolean[] i, Integer[] taint){
		return new TaintWrapper<Boolean[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Character[],Integer[]> getWrapper(Character[] i, Integer[] taint){
		return new TaintWrapper<Character[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Byte[],Integer[]> getWrapper(Byte[] i, Integer[] taint){
		return new TaintWrapper<Byte[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Short[],Integer[]> getWrapper(Short[] i, Integer[] taint){
		return new TaintWrapper<Short[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Integer[],Integer[]> getWrapper(Integer[] i, Integer[] taint){
		return new TaintWrapper<Integer[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Long[],Integer[]> getWrapper(Long[] i, Integer[] taint){
		return new TaintWrapper<Long[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Float[],Integer[]> getWrapper(Float[] i, Integer[] taint){
		return new TaintWrapper<Float[],Integer[]>(i,taint);
	}
	public static TaintWrapper<Double[],Integer[]> getWrapper(Double[] i, Integer[] taint){
		return new TaintWrapper<Double[],Integer[]>(i,taint);
	}	
	public static TaintWrapper<String[],Integer[]> getWrapper(String[] s, Integer[] taint){
		return new TaintWrapper<String[],Integer[]>(s,taint);
	}	
	public static TaintWrapper<String[],Integer[]> getWrapper(String[] s, int[] taint){
		return new TaintWrapper<String[],Integer[]>((String[])s,(Integer[])TaintTrackerConfig.box(taint));
	}
	public static <V,T> void setWrapperTaint(TaintWrapper<V,T> wrapper, T taint){
		wrapper.taint = taint;
	}
	
	public static int mergeTaints(int[] taints){
		int _return = 0;//TaintTrackerConfig.EMPTY_TAINT;
		for(int i : taints){
			_return |= i;
		}
		return _return;
	}
}