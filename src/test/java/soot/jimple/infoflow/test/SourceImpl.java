package soot.jimple.infoflow.test;

public class SourceImpl implements SourceIntf{
	private String secret;
	public SourceImpl(String secret){
		this.secret = secret;
	}
	
	@Override
	public String getData() {
		// TODO Auto-generated method stub
		return this.secret;
	}
}