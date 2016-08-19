package edu.tum.uc.transformer.analyzer;

import java.util.Set;

import org.objectweb.asm.MethodVisitor;

import edu.tum.uc.jvm.utility.analysis.SinkSourceSpec;
import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;

public class TaintSinkSource extends MethodVisitor {
	
	private MethodMetaInformation methodUtility;
	
	public TaintSinkSource(int api, MethodVisitor mv) {
		super(api, mv);
		// TODO Auto-generated constructor stub
	}
	
	public TaintSinkSource(int api, MethodVisitor mv, MethodMetaInformation methodUtility){
		this(api,mv);
		this.methodUtility = methodUtility;
	}
	
	public void visitCode(){
		mv.visitCode();
		System.out.println("TaintTraker "+this.methodUtility.getClassName()+", "+this.methodUtility.getMethodName());
	}
	
	@Override
	public void visitMethodInsn(int opcode, String owner, String name,
			String desc, boolean itf) {
		// TODO Auto-generated method stub
		super.visitMethodInsn(opcode, owner, name, desc, itf);
		Set<SinkSourceSpec> sources = TaintTrackerConfig.reader.getSources();
		Set<SinkSourceSpec> sinks = TaintTrackerConfig.reader.getSinks();
		for(SinkSourceSpec s : sources)
			System.out.println("--"+s.getClazz());
	}

}
