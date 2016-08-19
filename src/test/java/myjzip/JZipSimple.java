package myjzip;

import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;

public class JZipSimple {
	List<String> fileList;
	
	private int testAttr = 0;

	private Properties CONFIGURATION = null;

	private CommandLineParser cmdParser;
	private Options opt;
	private boolean run;
	private String[] args;
	private String commandline = "";
	
	public JZipSimple(int i) {
		this.testAttr = i;
	}

	private int testArith(int h, long r, char s){
		int a = h, b = 3444;
		double c = 4, d=500000;
		long e = 60000 +r;
		int sum = a+b;
		sum += this.testAttr;
		test();
		return sum;
	}
	
	private static void test(){
		System.out.println("Test");
		int[] a = new int[5];
		a[3] = 55;
		int c = a[3];
		a.clone();
	}
	
	private int source(){
		return 1;
	}
	private void sink(int i){
		System.out.println(i);
	}
	
	public static void main(String[] args) throws Throwable {
		JZipSimple jzip = new JZipSimple(5);
		List[] a = new LinkedList[50000];
		int i = 5;
		JZipSimple j = new JZipSimple(i);
		char s = '2';
		j.testArith(4, 5, s);
		int h = 3;
		i = j.source();
		i = i+h;
		j.sink(i);
//		invokedynamic();
	}
	
//	public static void invokedynamic() throws Throwable{
//		JZipSimple jzip = new JZipSimple(4);
//		MethodHandles.Lookup lookup = MethodHandles.lookup();
//		MethodHandle mh = lookup.findVirtual(JZipSimple.class, "test", MethodType.methodType(void.class));
//		mh.invoke(jzip);
//	}
	
}

/*
 * 			String type = TaintTrackerConfig.MULTI_TAINT_TRACKING ? TaintTrackerConfig.TAINT_DESC_ARR
					: TaintTrackerConfig.TAINT_DESC;
			int taintOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ALOAD
					: Opcodes.ILOAD;
			int tmpVar = this.createTmpVar(Type.INT_TYPE);
			// T-V-T-V
			super.visitVarInsn(Opcodes.ISTORE, tmpVar);
			// T-V-T
			super.visitInsn(Opcodes.SWAP);
			// T-T-V
			super.visitVarInsn(Opcodes.ILOAD, tmpVar);
			super.visitInsn(opcode);
			super.visitInsn(Opcodes.DUP_X2);
			super.visitInsn(Opcodes.POP);
			super.visitInsn(Opcodes.IOR);
			super.visitInsn(Opcodes.SWAP);
			
			if(this.localVarTmp.size() > 0){
			for(int key: this.localVarTmp.keySet()){
				LocalVariableNode n = this.localVarTmp.get(key);
				super.visitLocalVariable(n.name, n.desc, n.signature, n.start.getLabel(), n.end.getLabel(), n.index);
			}
			this.localVarTmp.clear();
		}
		
	private int createTmpVar(Type type) {
		int index = -1;
		index = super.newLocal(type);
		String locVarName = TaintTrackerConfig.wrapLocalTmpVar(String
				.valueOf(index));
		Label startLabel = new Label();
		super.visitLabel(startLabel);
		LocalVariableNode tmpLocVar = new LocalVariableNode(locVarName,
				type.getDescriptor(), null, new LabelNode(startLabel),
				new LabelNode(endLabel), index);
		this.localVarTmp.put(index, tmpLocVar);
		return index;
	}
		*
		*/
