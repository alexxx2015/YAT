import org.junit.Before;


public abstract class BasicTest {

	protected JavassistInstrumentor instrumentor;
	
	@Before
	public void init(){
		this.instrumentor = new JavassistInstrumentor();
	}
}
