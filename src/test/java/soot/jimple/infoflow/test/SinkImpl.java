package soot.jimple.infoflow.test;


public class SinkImpl implements SinkIntf{
	private String s;
	@Override
	public void setData(String p) {
		this.s = p;
	}
}
