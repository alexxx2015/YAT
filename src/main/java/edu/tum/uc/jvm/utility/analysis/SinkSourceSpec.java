package edu.tum.uc.jvm.utility.analysis;

public class SinkSourceSpec{
	public static enum TYPE {
		SINK, SOURCE
	};

	private String clazz;
	private String selector;
	private String params;
	private TYPE type;

	public SinkSourceSpec(TYPE t){
		this.type = t;
	}
	
	public String getClazz() {
		return clazz;
	}

	public void setClazz(String clazz) {
		this.clazz = clazz;
	}

	public String getSelector() {
		return selector;
	}

	public void setSelector(String selector) {
		this.selector = selector;
	}

	public String getParams() {
		return params;
	}

	public void setParams(String params) {
		this.params = params;
	}

	public TYPE getType() {
		return type;
	}
	
	public void setType(TYPE t){
		this.type = t;
	}
}
