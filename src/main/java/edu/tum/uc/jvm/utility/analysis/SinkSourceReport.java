package edu.tum.uc.jvm.utility.analysis;

import java.util.LinkedList;
import java.util.List;

import edu.tum.uc.jvm.utility.analysis.StaticAnalysis.NODETYPE;

public class SinkSourceReport {
	private String id;
	private String location;
	private int offset;
	private List<String> possibleSignatures;
	private boolean _return;
	private int param = -1000;
	private List<Integer> context;

	private NODETYPE type;

	public SinkSourceReport(NODETYPE type) {
		this.type = type;
	}

	public void addSignature(String signature) {
		if (this.possibleSignatures == null)
			this.possibleSignatures = new LinkedList<String>();
		this.possibleSignatures.add(signature);
	}

	public void addContext(int context) {
		if (this.context == null)
			this.context = new LinkedList<Integer>();
		this.context.add(context);
	}

	public void addContext(String context) {
		for (String s : context.split(",")) {
			this.addContext(Integer.parseInt(s));
		}
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public List<String> getPossibleSignatures() {
		return possibleSignatures;
	}

	public void setPossibleSignatures(List<String> possibleSignatures) {
		this.possibleSignatures = possibleSignatures;
	}

	public boolean is_return() {
		return _return;
	}

	public void set_return(boolean _return) {
		this._return = _return;
	}

	public int getParam() {
		return param;
	}

	public void setParam(int param) {
		this.param = param;
	}

	public List<Integer> getContext() {
		return context;
	}

	public void setContext(List<Integer> context) {
		this.context = context;
	}

	public NODETYPE getType() {
		return type;
	}

	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

	public String getContextAsString() {
		String s = "[";
		if (this.context != null) {
			for (int i = 0; i < this.context.size(); i++) {
				s += this.context.get(i) + ",";
			}
			if (s.charAt(s.length() - 1) == ',') {
				s = s.substring(0, s.length() - 1);
			}
		}
		return s + "]";
	}

}
