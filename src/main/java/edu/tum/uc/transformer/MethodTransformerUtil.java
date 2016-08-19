package edu.tum.uc.transformer;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AnalyzerAdapter;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;

import edu.tum.uc.jvm.utility.analysis.SinkSourceSpec;
import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;
import edu.tum.uc.transformer.taint.TaintWrapper;
import javassist.bytecode.Opcode;

final class MethodTransformerUtil {

	private Map<Integer, LocalVariableNode> localVar2Shadow;
	private Map<Integer, LocalVariableNode> localVar2Tmp;

	private MethodTransformer methodTransformer;
	protected Label endLabel;
	protected boolean visitedLabelEnd = false;

	MethodTransformerUtil(MethodTransformer methodTransformer) {
		this.methodTransformer = methodTransformer;
		this.endLabel = new Label();
		this.localVar2Shadow = new HashMap<Integer, LocalVariableNode>();
		this.localVar2Tmp = new HashMap<Integer, LocalVariableNode>();
	}

	// creates a shadow variable
	protected int createShadowVar(int opcode, int var, Type type) {
		int index = -1;
		LocalVariableNode shadowLocVar;
		if (this.localVar2Shadow.containsKey(var)) {
			shadowLocVar = this.localVar2Shadow.get(var);
			index = shadowLocVar.index;
		} else {
			index = this.methodTransformer.getLvs().newLocal(type);
			String locVarName = TaintTrackerConfig.wrapLocalVariable(String.valueOf(var));
			Label startLabel = new Label();
			this.methodTransformer.visitLabel(startLabel);
			shadowLocVar = new LocalVariableNode(locVarName, type.getDescriptor(), null, new LabelNode(startLabel),
					new LabelNode(this.endLabel), index);
			this.localVar2Shadow.put(var, shadowLocVar);
		}
		return index;
	}

	// creates a temporary variable
	protected int createTmpVar(Type type) {
		int index = -1;
		index = this.methodTransformer.getLvs().newLocal(type);
		String locVarName = TaintTrackerConfig.wrapLocalTmpVar(String.valueOf(index));
		Label startLabel = new Label();
		this.methodTransformer.visitLabel(startLabel);
		LocalVariableNode tmpLocVar = new LocalVariableNode(locVarName, type.getDescriptor(), null,
				new LabelNode(startLabel), new LabelNode(endLabel), index);
		this.localVar2Tmp.put(index, tmpLocVar);
		return index;
	}

	public Map<Integer, LocalVariableNode> getLocalVar2Shadow() {
		return this.localVar2Shadow;
	}

	public Map<Integer, LocalVariableNode> getLocalVar2Tmp() {
		return this.localVar2Tmp;
	}

	// wrap commands that operates on primitive types
	protected boolean wrapPrimTypeInsn(int opcode, MethodVisitor mv) {
		boolean _return = false;
		Type targetType = null;
		int targetLoadInstr = -10, targetStoreInstr = -10;

		if (opcode == Opcodes.IADD || opcode == Opcodes.ISHL || opcode == Opcodes.ISHR || opcode == Opcodes.ISUB
				|| opcode == Opcodes.IMUL || opcode == Opcodes.IDIV || opcode == Opcodes.IREM || opcode == Opcodes.IXOR
				|| opcode == Opcodes.IAND || opcode == Opcode.IOR || opcode == Opcodes.IUSHR) {
			targetType = Type.INT_TYPE;
			targetLoadInstr = Opcodes.ILOAD;
			targetStoreInstr = Opcodes.ISTORE;
		} else if (opcode == Opcodes.FADD || opcode == Opcodes.FSUB || opcode == Opcodes.FMUL || opcode == Opcodes.FDIV
				|| opcode == Opcodes.FREM) {
			targetType = Type.FLOAT_TYPE;
			targetLoadInstr = Opcodes.FLOAD;
			targetStoreInstr = Opcodes.FSTORE;
		} else if (opcode == Opcodes.DADD || opcode == Opcodes.DSUB || opcode == Opcodes.DMUL || opcode == Opcodes.DDIV
				|| opcode == Opcodes.DREM) {
			targetType = Type.DOUBLE_TYPE;
			targetLoadInstr = Opcodes.DLOAD;
			targetStoreInstr = Opcodes.DSTORE;
		} else if (opcode == Opcodes.LADD || opcode == Opcodes.LSHL || opcode == Opcodes.LSHR || opcode == Opcodes.LSUB
				|| opcode == Opcodes.LMUL || opcode == Opcodes.LDIV || opcode == Opcodes.LREM || opcode == Opcodes.LXOR
				|| opcode == Opcodes.LAND || opcode == Opcode.LOR || opcode == Opcodes.LUSHR) {
			targetType = Type.LONG_TYPE;
			targetLoadInstr = Opcodes.LLOAD;
			targetStoreInstr = Opcodes.LSTORE;
		}

		if (targetType != null && targetLoadInstr > 0 && targetStoreInstr > 0
				&& (targetType.equals(Type.INT_TYPE) || targetType.equals(Type.FLOAT_TYPE))) {
			// V-T-V-T on stack
			mv.visitInsn(Opcodes.SWAP);
			// V-T-T-V
			mv.visitInsn(Opcodes.DUP_X2);
			// V-V-T-T-V
			mv.visitInsn(Opcodes.POP);
			// V-V-T-T
			mv.visitInsn(Opcodes.IOR);
			// mv.visitInsn(Opcodes.DUP);
			// mv.visitMethodInsn(Opcodes.INVOKESTATIC, Logger.class.getName()
			// .replace(".", "/"), "log", "(I)V", false);

			// V-V-T
			mv.visitInsn(Opcodes.DUP_X2);
			// T-V-V-T
			mv.visitInsn(Opcodes.POP);
			// T-V-V
			mv.visitInsn(opcode);
			// T-V
			mv.visitInsn(Opcodes.SWAP);
			// V-T
			_return = true;
		} else if (targetType != null && targetLoadInstr > 0 && targetStoreInstr > 0
				&& (targetType.equals(Type.LONG_TYPE) || targetType.equals(Type.DOUBLE_TYPE))) {
			int tmpVar = this.createTmpVar(Type.INT_TYPE);
			int taintVarLoadOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ALOAD : Opcodes.ILOAD;
			int taintVarStoreOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ASTORE : Opcodes.ISTORE;
			// V-V-T-V-V-T
			mv.visitVarInsn(taintVarStoreOpcode, tmpVar);
			// V-V-T-V-V
			mv.visitInsn(Opcodes.DUP2_X1);
			mv.visitInsn(Opcodes.POP2);
			// V-V-V-V-T
			mv.visitVarInsn(taintVarLoadOpcode, tmpVar);
			// V-V-V-V-T-T
			mv.visitInsn(Opcodes.IOR);
			// mv.visitInsn(Opcodes.DUP);
			// mv.visitMethodInsn(Opcodes.INVOKESTATIC, Logger.class.getName()
			// .replace(".", "/"), "log", "(I)V", false);
			// V-V-V-V-T
			mv.visitVarInsn(taintVarStoreOpcode, tmpVar);
			// V-V-V-V
			mv.visitInsn(opcode);
			mv.visitVarInsn(taintVarLoadOpcode, tmpVar);

			_return = true;
		}

		/*
		 * if (targetType != null && targetLoadInstr > 0 && targetStoreInstr >
		 * 0) { // Assuming T-V-T-V on stack int tmpVar =
		 * this.createTmpVar(targetType); mv.visitVarInsn(targetStoreInstr,
		 * tmpVar); // T-V-T mv.visitInsn(Opcodes.SWAP); // T-T-V
		 * mv.visitVarInsn(targetLoadInstr, tmpVar); // T-T-V-V
		 * mv.visitInsn(opcode); // T-T-V mv.visitInsn(Opcodes.DUP_X2);
		 * mv.visitInsn(Opcodes.POP); mv.visitInsn(Opcodes.IOR);
		 * mv.visitInsn(Opcodes.SWAP); _return = true; }
		 */

		return _return;
	}

	public boolean isComputType2(Object o) {
		if (o == Opcodes.DOUBLE || o == Opcodes.LONG || o == Opcodes.TOP)
			return true;
		return false;
	}

	/**
	 * Generates instructions equivalent to an instruction DUP{N}_X{U}, e.g.
	 * DUP2_X1 will dup the top 2 elements under the 1 beneath them.
	 * 
	 * @param n
	 * @param u
	 */
	protected void DUPN_XU(int n, int u) {
		// if (TaintUtils.DEBUG_DUPSWAP)
		// System.out.println(name + ": DUP" + n + "_X" + u + analyzer.stack);
		switch (n) {
		case 1:
			switch (u) {
			case 1:
				this.methodTransformer.visitInsn(Opcodes.DUP_X1);
				break;
			case 2:
				this.methodTransformer.visitInsn(Opcodes.DUP_X2);
				break;
			case 3:
				// A B C D -> D A B C D
				LocalVariableNode d[] = storeToLocals(4);
				loadLV(0, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 4:
				d = storeToLocals(5);
				loadLV(0, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);

				freeLVs(d);
				break;
			default:
				throw new IllegalArgumentException("DUP" + n + "_" + u + " is unimp.");
			}
			break;
		case 2:
			switch (u) {
			case 1:
				LocalVariableNode[] d = storeToLocals(3);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 2:
				d = storeToLocals(4);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 3:
				d = storeToLocals(5);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 4:
				d = storeToLocals(6);
				loadLV(1, d);
				loadLV(0, d);

				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			default:
				throw new IllegalArgumentException("DUP" + n + "_" + u + " is unimp.");
			}
			break;
		case 3:
			switch (u) {
			case 0:
				LocalVariableNode[] d = storeToLocals(3);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 1:
				d = storeToLocals(4);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 2:
				d = storeToLocals(5);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 3:
				d = storeToLocals(6);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 4:
				d = storeToLocals(7);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(6, d);
				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			default:
				throw new IllegalArgumentException("DUP" + n + "_" + u + " is unimp.");
			}
			break;
		case 4:
			switch (u) {
			case 1:
				LocalVariableNode[] d = storeToLocals(5);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 2:
				d = storeToLocals(6);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 3:
				d = storeToLocals(7);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(6, d);
				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			case 4:
				d = storeToLocals(8);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				loadLV(7, d);
				loadLV(6, d);
				loadLV(5, d);
				loadLV(4, d);
				loadLV(3, d);
				loadLV(2, d);
				loadLV(1, d);
				loadLV(0, d);
				freeLVs(d);

				break;
			default:
				throw new IllegalArgumentException("DUP" + n + "_" + u + " is unimp.");
			}
			break;
		default:
			throw new IllegalArgumentException("DUP" + n + "_" + u + " is unimp.");
		}
		// if (TaintUtils.DEBUG_DUPSWAP)
		// System.out.println("POST " + name + ": DUP" + n + "_X" + u +
		// analyzer.stack);
	}

	/**
	 * Stores the top n stack elements as local variables. Returns an array of
	 * all of the lv indices. return[0] is the top element.
	 * 
	 * @param n
	 * @return
	 */
	protected LocalVariableNode[] storeToLocals(int n) {
		LocalVariableNode[] ret = new LocalVariableNode[n];
		// System.out.println("Store to locals top " + n);
		// System.out.println(analyzer.stack);
		AnalyzerAdapter analyzer = this.methodTransformer.getNeverNullAnalyzer();
		for (int i = 0; i < n; i++) {
			Type elType = null;
			if (analyzer.stack.get(analyzer.stack.size() - 1) == Opcodes.TOP)
				elType = getTypeForStackType(analyzer.stack.get(analyzer.stack.size() - 2));
			else
				elType = getTypeForStackType(analyzer.stack.get(analyzer.stack.size() - 1));
			ret[i] = new LocalVariableNode(null, elType.getDescriptor(), null, null, null, this.createTmpVar(elType));
			this.methodTransformer.visitVarInsn(elType.getOpcode(Opcodes.ISTORE), ret[i].index);
		}
		return ret;
	}

	protected void loadLV(int n, LocalVariableNode[] lvArray) {
		this.methodTransformer.visitVarInsn(Type.getType(lvArray[n].desc).getOpcode(Opcodes.ILOAD), lvArray[n].index);
	}

	public Type getTypeForStackType(Object obj) {
		if (obj == Opcodes.INTEGER)
			return Type.INT_TYPE;
		else if (obj == Opcodes.FLOAT)
			return Type.FLOAT_TYPE;
		else if (obj == Opcodes.DOUBLE)
			return Type.DOUBLE_TYPE;
		else if (obj == Opcodes.LONG)
			return Type.LONG_TYPE;
		else if (obj instanceof String)
			if (!(((String) obj).charAt(0) == '[') && ((String) obj).length() > 1)
				return Type.getType("L" + obj + ";");
			else
				return Type.getType((String) obj);
		else if (obj == Opcodes.NULL)
			return Type.getType("Ljava/lang/Object;");
		else if (obj instanceof Label || obj == Opcodes.UNINITIALIZED_THIS)
			return Type.getType("Luninitialized;");
		else
			return null;
	}

	public void freeLVs(LocalVariableNode[] lvns) {
		for (LocalVariableNode lvn : lvns) {
			this.freeTmpLV(lvn.index);
		}
	}

	public void freeTmpLV(int idx) {
		for (int key : this.localVar2Tmp.keySet()) {
			LocalVariableNode lvn = this.localVar2Tmp.get(key);
			if (lvn.index == idx) {
				Label lbl = new Label();
				this.methodTransformer.visitLabel(lbl);
				lvn.end = new LabelNode(lbl);
				return;
			}
		}
		// System.err.println(tmpLVs);
		throw new IllegalArgumentException("asked to free tmp lv " + idx + " but couldn't find it?");
	}

	// this method assumes that the top stack entry is a reference to a
	// TaintWrapper object
	public void unfoldWrapperValue(MethodVisitor mv, Type returnType) {
		String unfoldWrapperClass = "";
		String unfoldWrapperMethod = "";
		String unfoldWrapperMethodDesc = "";
		boolean isArray = (returnType.getSort() == Type.ARRAY);
		if (isArray)
			returnType = returnType.getElementType();

		switch (returnType.getSort()) {
		case Type.BYTE:
			unfoldWrapperClass = Byte.class.getName();
			unfoldWrapperMethod = "byteValue";
			unfoldWrapperMethodDesc = "()B";
			break;
		case Type.SHORT:
			unfoldWrapperClass = Short.class.getName();
			unfoldWrapperMethod = "shortValue";
			unfoldWrapperMethodDesc = "()S";
			break;
		case Type.INT:
			unfoldWrapperClass = Integer.class.getName();
			unfoldWrapperMethod = "intValue";
			unfoldWrapperMethodDesc = "()I";
			break;
		case Type.LONG:
			unfoldWrapperClass = Long.class.getName();
			unfoldWrapperMethod = "longValue";
			unfoldWrapperMethodDesc = "()J";
			break;
		case Type.FLOAT:
			unfoldWrapperClass = Float.class.getName();
			unfoldWrapperMethod = "floatValue";
			unfoldWrapperMethodDesc = "()F";
			break;
		case Type.DOUBLE:
			unfoldWrapperClass = Double.class.getName();
			unfoldWrapperMethod = "doubleValue";
			unfoldWrapperMethodDesc = "()D";
			break;
		case Type.BOOLEAN:
			unfoldWrapperClass = Boolean.class.getName();
			unfoldWrapperMethod = "booleanValue";
			unfoldWrapperMethodDesc = "()Z";
			break;
		case Type.CHAR:
			unfoldWrapperClass = Character.class.getName();
			unfoldWrapperMethod = "charValue";
			unfoldWrapperMethodDesc = "()C";
			break;
		case Type.OBJECT:
			if (TaintTrackerConfig.isString(returnType)) {
				unfoldWrapperClass = String.class.getName();
				unfoldWrapperMethod = "stringValue";
				unfoldWrapperMethodDesc = "()Ljava/lang/String;";
			}
			break;
		}

		Type primitiveWrapperType = TaintTrackerConfig.getPrimitiveWrapper(returnType.getDescriptor());
		String arrayPrefix = "";
		String taintWrapperGetMethod = "getValue";
		String taintWrapperGetTaintMethod = "getTaint";
		String taintWrapperType = primitiveWrapperType.getInternalName();
		String taintWrapperClassMethodDesc = TaintTrackerConfig.TAINT_WRAPPER_CLASS_METHOD_DESC;
		String taintWrapperClass = TaintTrackerConfig.TAINT_WRAPPER_CLASS;
		String taintWrapperClassMethod = TaintTrackerConfig.TAINT_WRAPPER_CLASS_METHOD;
		if (isArray) {
			arrayPrefix = "[";
//			taintWrapperGetMethod = "getValueArr";
//			taintWrapperGetTaintMethod = "getTaintArr";
			taintWrapperClassMethodDesc = TaintTrackerConfig.TAINT_DESC_ARR;
			taintWrapperType = arrayPrefix + primitiveWrapperType.getDescriptor();
			taintWrapperClassMethodDesc = TaintTrackerConfig.TAINT_WRAPPER_CLASS_METHOD_DESC;
			taintWrapperClass = arrayPrefix
					+ TaintTrackerConfig.makeBCSignature(TaintTrackerConfig.TAINT_WRAPPER_CLASS);
			taintWrapperClassMethod = TaintTrackerConfig.TAINT_WRAPPER_CLASS_METHOD;
		}
		arrayPrefix = "";
		String taintWrapperGetRetDesc = arrayPrefix
				+ TaintTrackerConfig.makeBCSignature(TaintTrackerConfig.unescapeStr(Object.class.getName()));

		// extract the value-field and taint-field of a TaintWrapper object, and
		// pushes them on the stack
		mv.visitInsn(Opcodes.DUP);
		mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
				taintWrapperGetMethod, "()" + taintWrapperGetRetDesc, false);
		// do checkcast to most generic class type
		mv.visitTypeInsn(Opcodes.CHECKCAST, taintWrapperType);
		// if it's not array, then also unfold value from primitive wrapper
		// object
		if (!isArray && !TaintTrackerConfig.isString(returnType))
			mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TaintTrackerConfig.unescapeStr(unfoldWrapperClass),
					unfoldWrapperMethod, unfoldWrapperMethodDesc, false);

		// O-V , extract taint from wrapper object O
		mv.visitInsn(Opcodes.SWAP);
		mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
				taintWrapperGetTaintMethod, "()"+taintWrapperGetRetDesc, false);
		mv.visitTypeInsn(Opcodes.CHECKCAST, taintWrapperClass);
		if (!isArray)
			mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, taintWrapperClass, taintWrapperClassMethod,
					taintWrapperClassMethodDesc, false);
		else
			mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "unbox", "([Ljava/lang/Integer;)[I", false);
	}

//	returns the sinksourcespec if a specific method invokation is a source, otherwise NULL is returned
	public SinkSourceSpec isSource(MethodMetaInformation mmi) {
		SinkSourceSpec _return = null;
		Set<SinkSourceSpec> sources = TaintTrackerConfig.reader.getSources();
		for (SinkSourceSpec s : sources) {
			if (s.getClazz().contains(mmi.getClassName()) && s.getSelector().contains(mmi.getMethodName())) {
				_return = s;
				break;
			}
		}
		return _return;
	}

	public SinkSourceSpec isSink(MethodMetaInformation mmi) {
		SinkSourceSpec _return = null;
		Set<SinkSourceSpec> sinks = TaintTrackerConfig.reader.getSinks();
		for (SinkSourceSpec s : sinks) {
			// System.out.println(s.getClazz() + ", " + mmi.getClassname()+",
			// "+s.getSelector()+", "+mmi.getMethodName());
			if (s.getClazz().contains(mmi.getClassName()) && s.getSelector().contains(mmi.getMethodName())) {
				_return = s;
				break;
			}
		}
		return _return;
	}
	/*
	 * 
	 * 
	 * public void taintSource(MethodVisitor mv, MethodMetaInformation
	 * mmiParentMethod, MethodMetaInformation mmiChildMethod) {
	 * 
	 * if (mmiChildMethod.getNewReturnType().getDescriptor().contains(
	 * TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName())) &&
	 * this.isSource(mmiChildMethod)) { int loadOpcode =
	 * TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ALOAD : Opcodes.ILOAD;
	 * int taintVar = TaintTrackerConfig.getNextTaint();
	 * mv.visitInsn(Opcodes.DUP); // mv.visitVarInsn(loadOpcode, taintVar);
	 * mv.visitLdcInsn(taintVar); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
	 * TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "addTaint",
	 * "(I)V", false); mv.visitFieldInsn(Opcodes.GETSTATIC,
	 * TaintTrackerConfig.unescapeStr(System.class.getName()), "out",
	 * "Ljava/io/PrintStream;"); mv.visitLdcInsn("Source passed " +
	 * mmiChildMethod.getClassname() + "." + mmiChildMethod.getMethodName());
	 * mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
	 * TaintTrackerConfig.unescapeStr(PrintStream.class.getName()), "println",
	 * "(Ljava/lang/String;)V", false); } }
	 */
}
