package soot.jimple.infoflow.test;

public class DataContainerImpl implements DataContainer {
	private String data;

	@Override
	public void setData(String data) {
		// TODO Auto-generated method stub
		this.data = data;
	}

	@Override
	public String getData() {
		// TODO Auto-generated method stub
		return this.data;
	}

}
