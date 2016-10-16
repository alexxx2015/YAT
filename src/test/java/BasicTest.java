import org.junit.Before;

public abstract class BasicTest {

	protected final String INSTRUMENTDIR = "/home/alex/instrumented/";
	protected JavassistInstrumentor instrumentor;
	
	protected MyClassLoader mcl;
	protected String mclWhiteList;
	protected String rootDir;

	@Before
	public void init() {
		// this.instrumentor = new JavassistInstrumentor();
		this.rootDir = "target/test-classes/";
		ClassLoader parent = this.getClass().getClassLoader();
		this.mcl = new MyClassLoader(parent, this.mclWhiteList, this.rootDir);
	}
}
