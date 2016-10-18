package edu.tum.uc.transformer;

import java.util.HashMap;
import java.util.Map;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AnalyzerAdapter;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.objectweb.asm.tree.LocalVariableNode;

import edu.tum.uc.jvm.utility.analysis.SinkSourceSpec;
import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;
import edu.tum.uc.transformer.taint.TaintWrapper;
import javassist.bytecode.Opcode;

public class MethodTransformer extends MethodVisitor {

	/**
	 * The method name.
	 */
	private String methodName;
	/**
	 * The name of the class this method belongs to.
	 */
	private String className;
	private String superName;
	/**
	 * The access flags of the method.
	 */
	private int access;
	/**
	 * The fully qualified name of this method consisting of the class and
	 * method names and the descriptor.
	 */
	private String fqName;
	/**
	 * The descriptor of the method.
	 */
	private String descriptor;
	/**
	 * The class writer being the end of the class-as-event-chain-processing.
	 */
	private ClassVisitor cv;
	/**
	 * Determines if Information Flow Tracking should be instrumented or not.
	 */
	private boolean ift = true;

	private LocalVariablesSorter lvs;

	private MethodTransformerUtil methodTransformerUtil;
	private AnalyzerAdapter analyzerAdapter;
	private MethodMetaInformation mmiParent;
	// Stores which local variables have been initialized
	private Map<Integer, Boolean> initLocVar = new HashMap<Integer, Boolean>();

	private ClassTransformer ctf;

	protected MethodTransformer(int api, MethodVisitor mv, MethodMetaInformation mmi, ClassVisitor cv, String superName,
			ClassTransformer ctf) {
		super(Opcodes.ASM5, mv);

		this.methodName = mmi.getMethodName();
		this.className = mmi.getClassName();
		this.superName = superName;
		this.access = mmi.getAccess();

		this.descriptor = mmi.getNewDesc();
		this.cv = cv;

		this.fqName = TaintTrackerConfig.unescapeStr(this.className) + "|" + this.methodName + this.descriptor;
		this.methodTransformerUtil = new MethodTransformerUtil(this);
		this.ctf = ctf;

		this.mmiParent = mmi;

		// if (p_mv instanceof NeverNullArgAnalyzerAdapter)
		// this.analyzer = (NeverNullArgAnalyzerAdapter) p_mv;
		// this.ift = Boolean.parseBoolean(ConfigProperties
		// .getProperty(ConfigProperties.PROPERTIES.IFT));
	}

	public void setAnalyzerAdapter(AnalyzerAdapter analyzer) {
		this.analyzerAdapter = analyzer;
	}

	public AnalyzerAdapter getNeverNullAnalyzer() {
		return this.analyzerAdapter;
	}

	public void setLvs(LocalVariablesSorter lvs) {
		this.lvs = lvs;
	}

	public Map<Integer, LocalVariableNode> getLocalVar2Shadow() {
		return this.methodTransformerUtil.getLocalVar2Shadow();
	}

	public Map<Integer, LocalVariableNode> getLocalVar2Tmp() {
		return this.methodTransformerUtil.getLocalVar2Tmp();
	}

	public LocalVariablesSorter getLvs() {
		return this.lvs;
	}

	public void visitFieldInsn(int opcode, String owner, String name, String desc) {
		Type ownerType = Type.getType(TaintTrackerConfig.makeBCSignature(owner));
		Type fieldType = Type.getType(desc);

		boolean isWhitelistedOwner = TaintTrackerConfig.isWhitelisted(owner);
		boolean isWhitelistedField = (fieldType.getSort() == Type.OBJECT)
				? TaintTrackerConfig.isWhitelisted(fieldType.getInternalName()) : false;

		// true if command works on an instrumentable object/class
		boolean noInstrField = (fieldType.getSort() == Type.OBJECT && !TaintTrackerConfig.isString(fieldType));
		noInstrField |= (fieldType.getSort() == Type.ARRAY && fieldType.getElementType().getSort() == Type.OBJECT
				&& !TaintTrackerConfig.isString(fieldType.getElementType()));

		String taintDesc = (fieldType.getSort() == Type.ARRAY) ? TaintTrackerConfig.TAINT_DESC_ARR
				: TaintTrackerConfig.TAINT_DESC;
		String taintIdName = TaintTrackerConfig.wrapWithTaintId(name);

		if (opcode == Opcodes.GETFIELD) {
			// get taint from owner object if class is not whitelisted
			if (!isWhitelistedOwner) {
				if (noInstrField) {
					mv.visitFieldInsn(opcode, owner, name, desc);
					mv.visitInsn(Opcodes.DUP);
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()), "getTaint",
							"(Ljava/lang/Object;)I", false);
					return;
				} else {
					mv.visitInsn(Opcodes.DUP);
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()), "getTaint",
							"(Ljava/lang/Object;)I", false);
					mv.visitInsn(Opcodes.SWAP);
					mv.visitFieldInsn(opcode, owner, name, desc);
					if (fieldType.getSize() == 2) {
						mv.visitInsn(Opcodes.DUP2_X1);
						mv.visitInsn(Opcodes.POP2);
					} else
						mv.visitInsn(Opcodes.SWAP);
				}
				return;
			}
			if (noInstrField) {
				mv.visitFieldInsn(opcode, owner, name, desc);
				return;
			}

			// O
			mv.visitInsn(Opcodes.DUP);
			// O-O
			mv.visitFieldInsn(opcode, owner, taintIdName, taintDesc);
			// O-T
			mv.visitInsn(Opcodes.SWAP);
			// T-O
			mv.visitFieldInsn(opcode, owner, name, desc);// Invoke original code
			// T-V
			if (fieldType.getSize() == 2) {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			} else {
				mv.visitInsn(Opcodes.SWAP);
			}
		} else if (opcode == Opcodes.GETSTATIC) {

			mv.visitFieldInsn(opcode, owner, name, desc);

			// if (!isWhitelistedOwner && noInstrField) {
			// mv.visitInsn(Opcodes.DUP);
			// mv.visitMethodInsn(Opcodes.INVOKESTATIC,
			// TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
			// "getTaint", "(Ljava/lang/Object;)I", false);
			// }
			// else if (!isWhitelistedOwner && !noInstrField){
			// mv.visitLdcInsn(owner);
			// mv.visitMethodInsn(Opcodes.INVOKESTATIC,
			// TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
			// "getTaint", "(Ljava/lang/String;)I", false);
			// }
			// else
			if (!noInstrField && !isWhitelistedOwner) {
				mv.visitLdcInsn(owner + "." + name);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"getTaint", "(Ljava/lang/String;)I", false);
			} else if (!noInstrField) {
				mv.visitFieldInsn(opcode, owner, taintIdName, taintDesc);
			}
			// V-T
		} else if (opcode == Opcodes.PUTFIELD) {
			// add taint to owner object
			if (!isWhitelistedOwner && noInstrField) {
				mv.visitInsn(Opcodes.DUP2);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"moveTaint", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
				mv.visitFieldInsn(opcode, owner, name, desc);
				return;
			}
			// field is either a non-string object or a non-string array
			else if (isWhitelistedOwner && noInstrField) {
				mv.visitInsn(Opcodes.DUP2);
				// O-F-O-F
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"getTaint", "(Ljava/lang/Object;)I", false);
				// O-F-O-FT
				mv.visitInsn(Opcodes.SWAP);
				// O-F-FT-O
				mv.visitInsn(Opcodes.DUP);
				// O-F-FT-O-O
				mv.visitFieldInsn(Opcodes.GETFIELD, owner, TaintTrackerConfig.TAINT_INSTANCEMARK,
						TaintTrackerConfig.TAINT_DESC);
				// O-F-FT-O-OT
				mv.visitInsn(Opcodes.SWAP);
				// O-F-FT-OT-O
				mv.visitInsn(Opcodes.DUP_X2);
				// O-F-O-FT-OT-O
				mv.visitInsn(Opcodes.POP);
				// O-F-O-FT-OT
				mv.visitInsn(Opcodes.IOR);
				// O-F-O-FTOT
				mv.visitFieldInsn(Opcodes.PUTFIELD, owner, TaintTrackerConfig.TAINT_INSTANCEMARK,
						TaintTrackerConfig.TAINT_DESC);
				// O-F
				mv.visitFieldInsn(opcode, owner, name, desc);
				return;
			}

			// O-V-T
			String tmpVarDesc = TaintTrackerConfig.TAINT_DESC;
			int tmpTaintStoreInstr = TaintTrackerConfig.TAINT_STORE_INSTR;
			int tmpTaintLoadInstr = TaintTrackerConfig.TAINT_LOAD_INSTR;
			boolean isArray = fieldType.getSort() == Type.ARRAY;
			if (isArray) {
				tmpVarDesc = TaintTrackerConfig.TAINT_DESC_ARR;
				tmpTaintStoreInstr = TaintTrackerConfig.TAINT_STORE_ARR_INSTR;
				tmpTaintLoadInstr = TaintTrackerConfig.TAINT_LOAD_ARR_INSTR;
			}

			int tmpTaintValue = this.methodTransformerUtil.createTmpVar(Type.getType(tmpVarDesc));
			// O-V-T
			mv.visitVarInsn(tmpTaintStoreInstr, tmpTaintValue);
			// O-V
			if (fieldType.getSize() == 2) {// Computational-type 2, 64-bit value
				// occupies two stack entries
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
				// V-O
			} else {
				mv.visitInsn(Opcodes.DUP_X1);
				mv.visitInsn(Opcodes.POP);
				// V-O
			}

			// V-O
			mv.visitInsn(Opcodes.DUP);
			// V-O-O
			if (isArray) {
				mv.visitVarInsn(Opcodes.ALOAD, tmpTaintValue);
				// V-O-O-T
				mv.visitFieldInsn(opcode, owner, taintIdName, taintDesc);
				// V-O
			} else {
				// Load taint mark from attribute's shadow var for whitelisted
				// objects
				if (isWhitelistedOwner) {
					// V-O-O-O
					mv.visitInsn(Opcodes.DUP);
					mv.visitFieldInsn(Opcodes.GETFIELD, owner, taintIdName, taintDesc);
				}
				// Load taint mark from runtimetracker's taint mapping table,
				// for
				// non-whitelisted objects -> BlackBox Object
				else {
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()), "getTaint",
							"(Ljava/lang/Object;)I", false);
				}

				// V-O-O-T1 |->T1=field taint or blackbox object taint
				mv.visitVarInsn(tmpTaintLoadInstr, tmpTaintValue);
				// V-O-O-T1-T
				mv.visitInsn(Opcodes.IOR);
				// V-O-O-T
				if (isWhitelistedOwner) {
					mv.visitFieldInsn(opcode, owner, taintIdName, taintDesc);
				} else {
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()), "setTaint",
							"(Ljava/lang/Object;I)V", false);
				}
			}
			// V-O
			if (fieldType.getSize() == 2) {// Computational-type 2 -> 64-bit
											// value
				// occupies two stack entries
				mv.visitInsn(Opcodes.DUP_X2);
			} else {
				mv.visitInsn(Opcodes.DUP_X1);
			}
			// O-V-O
			mv.visitInsn(Opcodes.POP);
			mv.visitFieldInsn(opcode, owner, name, desc);
		} else if (opcode == Opcodes.PUTSTATIC) {
			// move taint label of the top stack value to non-whitelisted class
			// object
			if (!isWhitelistedOwner && noInstrField) {
				mv.visitInsn(Opcodes.DUP);
				mv.visitLdcInsn(owner);
				mv.visitInsn(Opcodes.SWAP);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"moveTaint", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
				mv.visitFieldInsn(opcode, owner, name, desc);
				return;
			}

			// V-T
			// Load taint mark from runtimetracker's taint mapping table, for
			// non-whitelisted classes
			if (noInstrField) {
				mv.visitInsn(Opcodes.DUP);
				mv.visitInsn(Opcodes.DUP);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"getTaint", "(Ljava/lang/String;)I", false);
			}
			// Load taint mark from internal class attribute
			else {
				mv.visitFieldInsn(Opcodes.GETSTATIC, owner, taintIdName, taintDesc);
			}
			// V-T-T1
			mv.visitInsn(Opcodes.IOR);

			// V-T
			if (noInstrField) {
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"setTaint", "(Ljava/lang/Object;I)V", false);
			} else {
				// Store taint
				mv.visitFieldInsn(opcode, owner, taintIdName, taintDesc);
			}
			// V
			mv.visitFieldInsn(opcode, owner, name, desc);// Store real value
		} else {
			mv.visitFieldInsn(opcode, owner, name, desc);
		}
	}

	@Override
	public void visitVarInsn(int opcode, int var) {
		boolean _return = false;
		boolean isArray = false;
		if (opcode == Opcodes.RETURN || opcode == Opcodes.RET) {
			_return = true;
		} else if (opcode == Opcodes.ASTORE) {
			_return = true;
			if (this.analyzerAdapter.stack != null && this.analyzerAdapter.stack.size() > 0) {
				Object o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
				if (o instanceof String) {
					Type t = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
					if (t.getSort() == Type.ARRAY && (TaintTrackerConfig.isString(t.getElementType())
							|| t.getElementType().getSort() != Type.OBJECT)) {
						_return = false;
						isArray = true;
					} else if (TaintTrackerConfig.isString(t)) {
						_return = false;
					}
					/*
					 * else if (TaintTrackerConfig.isWhitelisted(t)){ // O-T
					 * mv.visitIntInsn(Opcodes.ALOAD, var);
					 * mv.visitInsn(Opcodes.SWAP); // O-O-T String owner =
					 * t.getInternalName().replace(".", "/");
					 * mv.visitFieldInsn(Opcodes.PUTFIELD, owner,
					 * TaintTrackerConfig.TAINT_INSTANCEMARK,
					 * TaintTrackerConfig.TAINT_DESC); // O
					 * mv.visitVarInsn(opcode, var); return; }
					 */
				}
			}
		} else if (opcode == Opcodes.ALOAD) {
			_return = true;
			// load array with taint values for array with primitive element
			// values
			Map<Integer, Integer> var2VarMap = this.mmiParent.getNewVar2Var();
			int oldVar = var2VarMap.containsKey(var) ? var2VarMap.get(var) : var;
			oldVar = var;
			if (this.analyzerAdapter.locals.size() > oldVar) {
				Object o = this.analyzerAdapter.locals.get(oldVar);
				if (o instanceof String) {
					Type t = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
					if (t.getSort() == Type.ARRAY && t.getElementType().getSort() != Type.ARRAY
							&& (t.getElementType().getSort() != Type.OBJECT
									|| TaintTrackerConfig.isString(t.getElementType()))) {
						_return = false;
						isArray = true;
					} else if (TaintTrackerConfig.isString(t)) {
						_return = false;
					}
					/*
					 * // in case of whitelisted object: load taint mark from
					 * internal object attribute else if
					 * (TaintTrackerConfig.isWhitelisted(t)){ // execute
					 * original command mv.visitVarInsn(opcode, var); // Load
					 * taint mark from internal object attribtue
					 * mv.visitInsn(Opcodes.DUP); String owner =
					 * t.getInternalName().replace(".", "/");
					 * mv.visitFieldInsn(Opcodes.GETFIELD, owner,
					 * TaintTrackerConfig.TAINT_INSTANCEMARK,
					 * TaintTrackerConfig.TAINT_DESC); return; }
					 */
				}
			}

		}
		// skip instrumentation if _return is set
		if (_return) {
			mv.visitVarInsn(opcode, var);
			return;
		}

		int taintVarOpcode = -1;
		int taintVarIndex = -1;
		boolean isParam = false;
		// Get variable's taint from arg-to-taint mapping
		if (var < this.mmiParent.getArgLastIndex() + this.mmiParent.getNewArgsOffset()) {
			Map<Integer, Integer> args2TaintMapping = this.mmiParent.getArgs2TaintMapping();
			if (args2TaintMapping.containsKey(var)) {
				taintVarIndex = args2TaintMapping.get(var);
				isParam = true;
			}
		}
		// Create new variable's taint
		else {
			taintVarIndex = this.methodTransformerUtil.createShadowVar(opcode, var,
					Type.getType(isArray ? TaintTrackerConfig.TAINT_DESC_ARR : TaintTrackerConfig.TAINT_DESC));
			// var += this.mmiParent.getNewArgsOffset();
		}

		if (opcode == Opcodes.ILOAD || opcode == Opcodes.DLOAD || opcode == Opcodes.LLOAD || opcode == Opcodes.FLOAD
				|| opcode == Opcodes.ALOAD) {
			taintVarOpcode = (TaintTrackerConfig.MULTI_TAINT_TRACKING || isArray) ? Opcodes.ALOAD : Opcodes.ILOAD;
			// Initialized local variable
			if (!isParam && isArray) {
				this.initLocVar.put(taintVarIndex, true);
			} else if (!isParam && !this.initLocVar.containsKey(taintVarIndex)) {
				mv.visitIntInsn(Opcodes.BIPUSH, 0);
				mv.visitVarInsn(Opcodes.ISTORE, taintVarIndex);
				this.initLocVar.put(taintVarIndex, true);
			}
			// load variable on stack
			mv.visitVarInsn(opcode, var);
			// load variable's taint on stack
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);
		} else if (opcode == Opcodes.ISTORE || opcode == Opcodes.DSTORE || opcode == Opcodes.LSTORE
				|| opcode == Opcodes.FSTORE || opcode == Opcodes.ASTORE) {
			taintVarOpcode = (TaintTrackerConfig.MULTI_TAINT_TRACKING || isArray) ? Opcodes.ASTORE : Opcodes.ISTORE;
			// store taint mark at the taint mark slot
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);
			// store value at the local variable slot
			mv.visitVarInsn(opcode, var);
			if (!this.initLocVar.containsKey(taintVarIndex)) {
				this.initLocVar.put(taintVarIndex, true);
			}
		} else {
			mv.visitVarInsn(opcode, var);
		}
	}

	@Override
	public void visitIntInsn(final int opcode, final int operand) {
		if (opcode == Opcodes.NEWARRAY) {
			// Remove taint label from stack
			mv.visitInsn(Opcodes.POP);
			// duplicate top stack entry, as this value specifies the array
			// length
			mv.visitInsn(Opcodes.DUP);
			// create taint array, that contains taint for each array element
			mv.visitIntInsn(opcode, Opcodes.T_INT);
			mv.visitInsn(Opcodes.SWAP);
			// create original array
			mv.visitIntInsn(opcode, operand);// T-A
			mv.visitInsn(Opcodes.SWAP);
		} else {
			// BIPUSH,SIPUSH
			mv.visitIntInsn(opcode, operand);
			// Push empty taint for constant value loading
			mv.visitInsn(TaintTrackerConfig.EMPTY_TAINT);
		}
	}

	@Override
	public void visitIincInsn(int var, int increment) {
		mv.visitIincInsn(var, increment);
	}

	@Override
	public void visitInsn(int opcode) {
		Object o = null;
		Type oType = null;
		switch (opcode) {
		case Opcodes.ARRAYLENGTH:
			boolean instrumented = false;
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			if (o instanceof String) {
				Type t = Type.getType((String) o);
				if (t.getSort() == Type.ARRAY && (TaintTrackerConfig.isString(t.getElementType())
						|| TaintTrackerConfig.isPrimitiveStackType(t.getElementType()))) {
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "mergeTaints", "([I)I",
							false);
					mv.visitInsn(Opcodes.SWAP);
					mv.visitInsn(opcode);
					mv.visitInsn(Opcodes.SWAP);
					instrumented = true;
				}
			}
			if (!instrumented)
				mv.visitInsn(opcode);
			return;
		case Opcodes.IRETURN:
		case Opcodes.LRETURN:
		case Opcodes.FRETURN:
		case Opcodes.DRETURN:
			switch (opcode) {
			case Opcodes.IRETURN:
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
						"getWrapper", "(II)Ledu/tum/uc/transformer/taint/TaintWrapper;", false);
				break;
			case Opcodes.LRETURN:
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
						"getWrapper", "(JI)Ledu/tum/uc/transformer/taint/TaintWrapper;", false);
				break;
			case Opcodes.FRETURN:
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
						"getWrapper", "(FI)Ledu/tum/uc/transformer/taint/TaintWrapper;", false);
				break;
			case Opcodes.DRETURN:
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
						"getWrapper", "(DI)Ledu/tum/uc/transformer/taint/TaintWrapper;", false);
				break;
			}
			mv.visitInsn(Opcodes.ARETURN);
			return;
		case Opcodes.RETURN:
			// execute original opcode instruction
			mv.visitInsn(opcode);
			return;
		case Opcodes.ARETURN:
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			if (o instanceof String) {
				Type tz = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
				boolean isArray = tz.getSort() == Type.ARRAY;
				tz = (tz.getSort() == Type.ARRAY) ? tz.getElementType() : tz;
				if (tz.getSort() != Type.OBJECT || TaintTrackerConfig.isString(tz)) {
					String taintDesc = (isArray) ? TaintTrackerConfig.TAINT_DESC_ARR : TaintTrackerConfig.TAINT_DESC;
					String getWrapperDesc = "(" + tz.getDescriptor() + taintDesc + ")" + TaintTrackerConfig
							.makeBCSignature(TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()));
					mv.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "getWrapper", getWrapperDesc,
							false);
				}
			}
			mv.visitInsn(opcode);
			return;
		case Opcodes.ICONST_0:
		case Opcodes.ICONST_1:
		case Opcodes.ICONST_2:
		case Opcodes.ICONST_3:
		case Opcodes.ICONST_4:
		case Opcodes.ICONST_5:
		case Opcodes.ICONST_M1:
		case Opcodes.LCONST_0:
		case Opcodes.LCONST_1:
		case Opcodes.FCONST_0:
		case Opcodes.FCONST_1:
		case Opcodes.FCONST_2:
		case Opcodes.DCONST_0:
		case Opcodes.DCONST_1:
			// case Opcodes.ACONST_NULL:
			// execute original opcode instruction
			mv.visitInsn(opcode);
			// push empty taint on stack
			mv.visitIntInsn(Opcodes.BIPUSH, (byte) 0);
			return;
		case Opcodes.AASTORE:
			boolean instrumOpcode = false;
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 3);
			if (o instanceof String) {
				oType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			}

			// add usual instrumentation if string-array
			if (oType != null && oType.getSort() == Type.ARRAY
					&& (TaintTrackerConfig.isString(oType.getElementType()))) {
				// ARR-TArr-Idx-TIdx-Val-TVal
			}
			// add usual instrumentation is primitive-array
			else {
				o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
				if (o instanceof String) {
					oType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
					// remove taint mark from array element if its typed String
					if (oType != null && TaintTrackerConfig.isString(oType)) {
						mv.visitInsn(Opcodes.POP);
					}
				}
				// ARR-Idx-TIdx-Val
				mv.visitInsn(Opcodes.SWAP);
				// ARR-Idx-Val-TIdx
				mv.visitInsn(Opcodes.POP);
				// ARR-Idx-Val
				mv.visitInsn(opcode);
				return;
			}
		case Opcodes.IASTORE:
		case Opcodes.LASTORE:
		case Opcodes.DASTORE:
		case Opcodes.FASTORE:
		case Opcodes.BASTORE:
		case Opcodes.SASTORE:
		case Opcodes.CASTORE:
			// creates tmp-var for taint value
			int tmpTaintValue = this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));

			// create tmp-var for taint idx
			int tmpTaintIdx = this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));

			// create tmp-var for taint-array
			int tmpTaintArray = this.methodTransformerUtil
					.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC_ARR));

			// creates tmp-var for the value
			Type valueType = null;
			int tmpValueStoreOpcode = Opcodes.ISTORE;
			int tmpValueLoadOpcode = Opcodes.ILOAD;
			switch (opcode) {
			case Opcodes.IASTORE:
				valueType = Type.INT_TYPE;
				break;
			case Opcodes.LASTORE:
				valueType = Type.LONG_TYPE;
				tmpValueStoreOpcode = Opcodes.LSTORE;
				tmpValueLoadOpcode = Opcodes.LLOAD;
				break;
			case Opcodes.DASTORE:
				valueType = Type.DOUBLE_TYPE;
				tmpValueStoreOpcode = Opcodes.DSTORE;
				tmpValueLoadOpcode = Opcodes.DLOAD;
				break;
			case Opcodes.FASTORE:
				valueType = Type.FLOAT_TYPE;
				tmpValueStoreOpcode = Opcodes.FSTORE;
				tmpValueLoadOpcode = Opcodes.FLOAD;
				break;
			case Opcodes.BASTORE:
				valueType = Type.BOOLEAN_TYPE;
				break;
			case Opcodes.SASTORE:
				valueType = Type.SHORT_TYPE;
				break;
			case Opcodes.CASTORE:
				valueType = Type.CHAR_TYPE;
				break;
			case Opcodes.AASTORE:
				if ((oType != null && oType.getSort() == Type.ARRAY
						&& (TaintTrackerConfig.isString(oType.getElementType())))
						|| (oType != null && TaintTrackerConfig.isString(oType))) {
					valueType = oType;
					tmpValueStoreOpcode = Opcodes.ASTORE;
					tmpValueLoadOpcode = Opcodes.ALOAD;
				}
			}
			int tmpValue = this.methodTransformerUtil.createTmpVar(valueType);

			// creates tmp-var for the index
			int tmpIdx = this.methodTransformerUtil.createTmpVar(Type.INT_TYPE);

			// REF - TREF - IDX - TIDX - VAL - TVAL
			mv.visitIntInsn(Opcodes.ISTORE, tmpTaintValue);
			// REF - TREF - IDX - TIDX - VAL
			mv.visitIntInsn(tmpValueStoreOpcode, tmpValue);
			// REF - TREF - IDX - TIDX
			// mv.visitIntInsn(Opcodes.ISTORE, tmpTaintIdx);
			mv.visitInsn(Opcodes.POP);
			// REF - TREF - IDX
			mv.visitIntInsn(Opcodes.ISTORE, tmpIdx);
			// REF - TREF
			mv.visitIntInsn(Opcodes.ASTORE, tmpTaintArray);
			// REF
			mv.visitIntInsn(Opcodes.ILOAD, tmpIdx);
			// REF - IDX
			mv.visitIntInsn(tmpValueLoadOpcode, tmpValue);
			// REF - IDX - VAL
			mv.visitInsn(opcode); // Store actual value at the corresponding
									// position within the array
			mv.visitIntInsn(Opcodes.ALOAD, tmpTaintArray);
			// TREF
			mv.visitIntInsn(Opcodes.ILOAD, tmpIdx);// tmpTaintIdx);
			// TREF - TIDX
			mv.visitIntInsn(Opcodes.ILOAD, tmpTaintValue);
			// TREF - TIDX - TVAL
			mv.visitIntInsn(Opcodes.ALOAD, tmpTaintArray);
			// TREF - TIDX - TVAL - TREF
			mv.visitIntInsn(Opcodes.ILOAD, tmpIdx);// tmpTaintIdx);
			// TREF - TIDX - TVAL - TREF - TIDX
			mv.visitInsn(Opcodes.IALOAD);
			// TREF - TIDX - TVAL - TVAL2
			mv.visitInsn(Opcodes.IOR);
			// TREF - TIDX - TVAL+2
			mv.visitInsn(Opcodes.IASTORE);
			return;
		case Opcodes.AALOAD:
			instrumOpcode = false;
			if (this.analyzerAdapter.stack.size() >= 2) {
				o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 2);
				if (o instanceof String) {
					Type t = Type.getType((String) o);
					// add usual instrumentaiton if string-array
					if (t.getSort() == Type.ARRAY && (TaintTrackerConfig.isString(t.getElementType()))) {
						instrumOpcode = true;
					}
					// add usual instrumentation is primitive-array
					else if (t.getSort() == Type.ARRAY && t.getElementType().getSort() != Type.OBJECT
							&& t.getElementType().getSort() != Type.ARRAY) {
						instrumOpcode = true;
					}
				}
			}
			if (!instrumOpcode) {
				mv.visitInsn(opcode);
				break;
			}
		case Opcodes.IALOAD:
		case Opcodes.LALOAD:
		case Opcodes.DALOAD:
		case Opcodes.FALOAD:
		case Opcodes.BALOAD:
		case Opcodes.SALOAD:
		case Opcodes.CALOAD:
			// create tmp-var for taint idx
			// tmpTaintIdx =
			// this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));

			// creates tmp-var for the index
			// tmpIdx = this.methodTransformerUtil.createTmpVar(Type.INT_TYPE);

			// REF - TREF - IDX - TIDX
			// mv.visitIntInsn(Opcodes.ISTORE, tmpTaintIdx);
			mv.visitInsn(Opcodes.POP);// Opcodes.SWAP
			// REF - TREF - IDX
			// mv.visitIntInsn(Opcodes.ISTORE, tmpIdx);
			mv.visitInsn(Opcodes.DUP_X1);
			// REF - IDX - TREF - IDX // mv.visitIntInsn(Opcodes.ILOAD,
			// tmpTaintIdx);// REF - TREF - TIDX
			mv.visitInsn(Opcodes.IALOAD);
			// REF - IDX - TVAL
			mv.visitInsn(Opcodes.DUP_X2);// Opcodes.SWAP);
			mv.visitInsn(Opcodes.POP);
			// mv.visitIntInsn(Opcodes.ILOAD, tmpIdx);
			// TVAL - REF - IDX
			mv.visitInsn(opcode);// Load actual value from array on the stack
			// TVAL - VAL
			if (opcode == Opcodes.LALOAD || opcode == Opcodes.DALOAD) {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			} else
				mv.visitInsn(Opcodes.SWAP);
			// VAL - TVAL
			return;
		case Opcodes.POP:
		case Opcodes.POP2:
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			if (o instanceof String) {
				Type t = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
				if (TaintTrackerConfig.isString(t)) {
					mv.visitInsn(Opcodes.POP);
				} else if (t.getSort() == Type.ARRAY && TaintTrackerConfig.isString(t.getElementType())) {
					mv.visitInsn(Opcodes.POP);
				}
			} else if (!this.analyzerAdapter.uninitializedTypes.containsKey(o)) {
				mv.visitInsn(Opcodes.POP);
			}
			mv.visitInsn(opcode);
			return;
		}

		// DUP
		if (opcode == Opcodes.DUP) {
			// X-V-T -> X-V-T-V-T
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			Type type = null;
			if (this.analyzerAdapter.uninitializedTypes.containsKey(o)) {
				o = this.analyzerAdapter.uninitializedTypes.get(o);
			}
			type = Type.getType(TaintTrackerConfig.makeBCSignature(o.toString()));

			if (TaintTrackerConfig.isPrimitiveStackType(o) || TaintTrackerConfig.isString(type)
					|| (type.getSort() == Type.ARRAY && TaintTrackerConfig.isString(type.getElementType()))) {
				mv.visitInsn(Opcodes.DUP2);
			} else {
				mv.visitInsn(opcode);
			}
		}
		// DUP_X1
		else if (opcode == Opcodes.DUP_X1) {
			// X-T-V-T -> X-T-V-T-X-T
			Object top = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			Object snd = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 2);
			if (TaintTrackerConfig.isPrimitiveStackType(top) && TaintTrackerConfig.isPrimitiveStackType(snd)) {
				mv.visitInsn(Opcodes.DUP2_X2);
			}
		}
		// DUP_X2
		else if (opcode == Opcodes.DUP_X2) {
			Object top = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			// DUP_X2 only works if top stack is of computational type 1
			if (!this.methodTransformerUtil.isComputType2(top)) {
				Object snd, trd;
				snd = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 2);

				// Top stack-element primitiv
				if (TaintTrackerConfig.isPrimitiveStackType(top)) {
					// second stack-element primitiv
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						// second element comp. type 2
						if (this.methodTransformerUtil.isComputType2(snd)) {
							this.methodTransformerUtil.DUPN_XU(2, 3);
						} else {
							trd = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 3);
							if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
								this.methodTransformerUtil.DUPN_XU(2, 4);
							} else {
								this.methodTransformerUtil.DUPN_XU(2, 3);
							}
						}
					}
					// second stack-element is not primitiv
					else {
						trd = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							this.methodTransformerUtil.DUPN_XU(2, 3);
						} else {
							mv.visitInsn(Opcodes.DUP2_X2);
						}
					}
				}
				// Top stack-element is not primitive
				else {
					// Second is primitiv type?
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						// Second is computational type 2
						if (this.methodTransformerUtil.isComputType2(snd)) {
							// Dup the top 1 element to be under the 3 beneath.
							LocalVariableNode d[] = this.methodTransformerUtil.storeToLocals(3);
							this.methodTransformerUtil.loadLV(0, d);
							this.methodTransformerUtil.loadLV(2, d);
							this.methodTransformerUtil.loadLV(1, d);
							this.methodTransformerUtil.loadLV(0, d);
							this.methodTransformerUtil.freeLVs(d);
						} else {
							trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
							if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
								// Dup the top 1 under the next 4
								this.methodTransformerUtil.DUPN_XU(1, 4);
							} else {
								// Dup the top 1 under the next 3, because trd
								// is a reference value
								this.methodTransformerUtil.DUPN_XU(1, 3);
							}
						}
					} else {
						trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							// Dup the top 1 under the next 3
							this.methodTransformerUtil.DUPN_XU(1, 3);
						} else {
							// Dup the top 1 under the next 2
							mv.visitInsn(Opcodes.DUP_X2);
						}
					}
				}
			} else {
				mv.visitInsn(Opcodes.DUP_X2);
			}
		}
		// DUP2
		else if (opcode == Opcodes.DUP2) {
			Object topStackElement = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			if (this.methodTransformerUtil.isComputType2(topStackElement)) {
				// duplicate a double or a long, those value is spread over two
				// consecutive stack words
				// V-V-T
				mv.visitInsn(Opcodes.DUP_X2);
				// T-V-V-T
				int tmpVar = this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));
				mv.visitVarInsn(Opcodes.ISTORE, tmpVar);
				// T-V-V
				mv.visitInsn(Opcodes.DUP2_X1);
				// V-V-T-V-V
				mv.visitVarInsn(Opcodes.ILOAD, tmpVar);
				// V-V-T-V-V-T
			} else {
				Object sndOnStack = this.analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);

				// V1-T1-V2-T2
				int top = this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));
				int snd = this.methodTransformerUtil.createTmpVar(Type.getType(TaintTrackerConfig.TAINT_DESC));

				mv.visitVarInsn(Opcodes.ISTORE, top);
				mv.visitVarInsn(Opcodes.ISTORE, snd);
				// V1-T1

				mv.visitInsn(Opcodes.DUP2);
				// V1-T1-V1-T1

				mv.visitVarInsn(Opcodes.ILOAD, snd);
				mv.visitVarInsn(Opcodes.ILOAD, top);
				// V1-T1-V1-T1-V2-T2

				// V1-T1-V2-T2-V1-T1-V2-T2
				if (TaintTrackerConfig.isPrimitiveStackType(sndOnStack)) {
					mv.visitInsn(Opcodes.DUP2_X2);
				} else {
					mv.visitInsn(Opcodes.DUP);
				}
			}
		}
		// DUP2_X1
		else if (opcode == Opcodes.DUP2_X1) {
			Object top = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 1);
			if (TaintTrackerConfig.isPrimitiveStackType(top)) {
				if (this.methodTransformerUtil.isComputType2(top)) {
					// Have two-word el + 1 word taint on top
					Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						// Dup the top three words to be under the 2 words
						// beneath them
						this.methodTransformerUtil.DUPN_XU(2, 2);
					} else {
						// Dup the top three words to be under the word beneath
						// them
						this.methodTransformerUtil.DUPN_XU(2, 1);
					}
				} else // top is 1 word, primitive
				{
					Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						// top is primitive, second is primitive
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							// Dup the top four words to be under the 2 beneath
							// them
							this.methodTransformerUtil.DUPN_XU(4, 2);
						} else {
							// dup the top four words to be under the 1 beneath
							this.methodTransformerUtil.DUPN_XU(4, 1);
						}
					} else {
						// top is primitive, second is not
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							// TV VTV
							// Dup the top three words to be under the 2 beneath
							this.methodTransformerUtil.DUPN_XU(3, 2);
						} else {
							// dup the top three words to be under the 1 beneath
							this.methodTransformerUtil.DUPN_XU(3, 1);
						}
					}
				}
			} else {
				// top is not primitive. must be one word.
				Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
				if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
					Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
					if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
						// Dup the top 3 words to be under the 2 beneath
						this.methodTransformerUtil.DUPN_XU(3, 2);
					} else {
						// dup the top 3 words to be under the 1 beneath
						this.methodTransformerUtil.DUPN_XU(3, 1);
					}
				} else {
					Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
					if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
						// Dup the top 2 words to be under the 2 beneath
						mv.visitInsn(Opcodes.DUP2_X2);
					} else {
						// dup the top 2 words to be under the 1 beneath
						mv.visitInsn(Opcodes.DUP2_X1);
					}
				}
			}
		}
		// DUP2_X2
		else if (opcode == Opcodes.DUP2_X2) {
			Object top = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 1);
			if (TaintTrackerConfig.isPrimitiveStackType(top)) {
				if (this.methodTransformerUtil.isComputType2(top)) {
					// Have two-word el + 1 word taint on top
					Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							// Dup the top three words to be under the 4 words
							// beneath them
							this.methodTransformerUtil.DUPN_XU(2, 4);
						} else {
							// Dup the top three words to be under the 3 words
							// beneath them
							this.methodTransformerUtil.DUPN_XU(2, 3);
						}
					} else {
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							// Dup the top three words to be under the 4 words
							// beneath them
							this.methodTransformerUtil.DUPN_XU(2, 3);
						} else {
							// Dup the top three words to be under the 2 words
							// beneath them
							this.methodTransformerUtil.DUPN_XU(2, 2);
						}
					}
				} else // top is 1 word, primitive
				{
					Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
					if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
						// top is primitive, second is primitive
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
							if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
								this.methodTransformerUtil.DUPN_XU(4, 4);
							} else {
								this.methodTransformerUtil.DUPN_XU(4, 3);
							}
						} else {
							Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
							if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
								this.methodTransformerUtil.DUPN_XU(4, 3);
							} else {
								this.methodTransformerUtil.DUPN_XU(4, 2);
							}
						}
					} else {
						// top is primitive, second is not
						Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
							Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
							if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
								this.methodTransformerUtil.DUPN_XU(3, 4);
							} else {
								this.methodTransformerUtil.DUPN_XU(3, 3);
							}

						} else {
							Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
							if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
								this.methodTransformerUtil.DUPN_XU(3, 3);
							} else {
								this.methodTransformerUtil.DUPN_XU(3, 2);
							}
						}
					}
				}
			} else {
				// top is not primitive. must be one word.
				Object snd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 2);
				if (TaintTrackerConfig.isPrimitiveStackType(snd)) {
					Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
					if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
						Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
							this.methodTransformerUtil.DUPN_XU(3, 4);
						} else {
							this.methodTransformerUtil.DUPN_XU(3, 3);
						}

					} else {
						Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
							this.methodTransformerUtil.DUPN_XU(3, 3);
						} else {
							this.methodTransformerUtil.DUPN_XU(3, 2);
						}
					}
				} else {
					Object trd = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 3);
					if (TaintTrackerConfig.isPrimitiveStackType(trd)) {
						mv.visitInsn(Opcodes.DUP2_X2);
						Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
							this.methodTransformerUtil.DUPN_XU(2, 4);
						} else {
							this.methodTransformerUtil.DUPN_XU(2, 3);
						}

					} else {
						Object fourth = analyzerAdapter.stack.get(analyzerAdapter.stack.size() - 4);
						if (TaintTrackerConfig.isPrimitiveStackType(fourth)) {
							this.methodTransformerUtil.DUPN_XU(2, 3);
						} else {
							mv.visitInsn(Opcodes.DUP2_X2);
						}
					}
				}
			}
		} else if (opcode == Opcodes.I2B || opcode == Opcodes.I2C || opcode == Opcodes.I2D || opcode == Opcodes.I2F
				|| opcode == Opcodes.I2L || opcode == Opcodes.I2S) {
			// V-T
			mv.visitInsn(Opcodes.SWAP);
			// T-V
			mv.visitInsn(opcode);
			// T-V
			if (opcode == Opcodes.I2L || opcode == Opcodes.I2D) {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			} else
				mv.visitInsn(Opcodes.SWAP);
			// V-T
		} else if (opcode == Opcodes.L2D || opcode == Opcodes.L2F || opcode == Opcodes.L2I) {
			// V-T
			mv.visitInsn(Opcodes.DUP_X2);
			mv.visitInsn(Opcodes.POP);
			// T-V
			mv.visitInsn(opcode);
			if (opcode == Opcodes.L2D) {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			} else
				mv.visitInsn(Opcodes.SWAP);
			// V-T
		} else if (opcode == Opcodes.F2D || opcode == Opcodes.F2I || opcode == Opcodes.F2L) {
			// V-T
			mv.visitInsn(Opcodes.SWAP);
			// T-V
			mv.visitInsn(opcode);
			if (opcode == Opcodes.F2I) {
				mv.visitInsn(Opcodes.SWAP);
			} else {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			}
		} else if (opcode == Opcodes.D2F || opcode == Opcodes.D2I || opcode == Opcodes.D2L) {
			// V-T
			mv.visitInsn(Opcodes.DUP_X2);
			mv.visitInsn(Opcodes.POP);
			// T-V
			mv.visitInsn(opcode);
			if (opcode == Opcodes.D2L) {
				mv.visitInsn(Opcodes.DUP2_X1);
				mv.visitInsn(Opcodes.POP2);
			} else
				mv.visitInsn(Opcodes.SWAP);
		} else if (opcode == Opcodes.INEG || opcode == Opcodes.FNEG) {
			mv.visitInsn(Opcodes.SWAP);
			mv.visitInsn(opcode);
			mv.visitInsn(Opcodes.SWAP);
		} else if (opcode == Opcodes.LNEG || opcode == Opcodes.DNEG) {
			mv.visitInsn(Opcodes.DUP_X2);
			mv.visitInsn(Opcodes.POP);
			mv.visitInsn(opcode);
			mv.visitInsn(Opcodes.DUP2_X1);
			mv.visitInsn(Opcodes.POP2);
		}
		// wrap command if it operates on primitive types
		else if (this.methodTransformerUtil.wrapPrimTypeInsn(opcode, mv)) {
			// mv.visitInsn(opcode);
		} else {
			mv.visitInsn(opcode);
		}
	}

	@Override
	public void visitLdcInsn(Object cst) {
		// load value from constant pool
		mv.visitLdcInsn(cst);
		// load empty taint on stack
		if (cst instanceof Integer || cst instanceof Float || cst instanceof Long || cst instanceof Double
				|| cst instanceof String)
			mv.visitInsn(TaintTrackerConfig.EMPTY_TAINT);
	}

	@Override
	public void visitJumpInsn(int opcode, Label label) {
		Object o = null;
		Type oType = null;
		// this opcode checks if top stack element is null, if so the execution
		// proceeds at label's offset
		switch (opcode) {
		// O-T
		case Opcodes.IFNULL:// SUCCEEDS: O==null
		case Opcodes.IFNONNULL:// SUCCEEDS: O!=null
			o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 1);
			if (o instanceof String) {
				oType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			} else if (this.analyzerAdapter.uninitializedTypes.containsKey(o)) {
				o = this.analyzerAdapter.uninitializedTypes.get(o);
				oType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			}
			if (TaintTrackerConfig.isString(oType))
				mv.visitInsn(Opcodes.POP);
			else if (oType.getSort() == Type.ARRAY && TaintTrackerConfig.isString(oType.getElementType()))
				mv.visitInsn(Opcodes.POP);
			mv.visitJumpInsn(opcode, label);
			return;
		// V-T
		case Opcodes.IFEQ:// SUCCEEDS: V==0
		case Opcodes.IFNE:// SUCCEEDS: V!=0
		case Opcodes.IFLT:// SUCCEEDS: V<0
		case Opcodes.IFLE:// SUCCEEDS: V<=0
		case Opcodes.IFGT:// SUCCEEDS: V>0
		case Opcodes.IFGE:// SUCCEEDS: V>=0
			mv.visitInsn(Opcodes.POP);
			break;
		case Opcodes.IF_ICMPEQ:// succeeds value1 = value2
		case Opcodes.IF_ICMPGE:// succeeds value1 >= value2
		case Opcodes.IF_ICMPGT:// succeeds value1 > value2
		case Opcodes.IF_ICMPLE:// succeeds value1 <= value2
		case Opcodes.IF_ICMPLT:// succeeds value1 < value2
		case Opcodes.IF_ICMPNE:// succeeds value1 != value2
			// V-T-V-T
			mv.visitInsn(Opcodes.POP);
			// V-T-V
			mv.visitInsn(Opcodes.DUP_X1);
			// V-V-T-V
			mv.visitInsn(Opcodes.POP2);
			break;
		}

		mv.visitJumpInsn(opcode, label);
	}

	@Override
	public void visitTypeInsn(int opcode, String type) {

		// array of references contain their taint label inside the object or in
		// the outsourced hashmap
		if (opcode == Opcodes.ANEWARRAY) {
			mv.visitInsn(Opcodes.POP);
			mv.visitTypeInsn(opcode, type);
			if (TaintTrackerConfig.isString(type)) {
				mv.visitInsn(Opcode.DUP);
				mv.visitInsn(Opcodes.ARRAYLENGTH);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC,
						TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "getEmptyTaint", "(I)[I",
						false);
			}
			return;
		} else if (opcode == Opcodes.CHECKCAST) {
			Type t = Type.getType(TaintTrackerConfig.makeBCSignature(type));
			if (TaintTrackerConfig.isString(t)) {
				mv.visitTypeInsn(opcode, type);
				mv.visitIntInsn(Opcodes.BIPUSH, 0);
				;// TODO: retrieve the actual
					// taint for string
				return;
			}
		}
		// execute original instruction
		mv.visitTypeInsn(opcode, type);
	}

	@Override
	public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
		if (TaintTrackerConfig.isMainMethod(opcode, owner, name, desc, itf)) {
			mv.visitInsn(Opcodes.POP);
			mv.visitMethodInsn(opcode, owner, name, desc, itf);
			return;
		}

		// Wrap each original method invocation into another method that
		// includes taint parameters
		StringBuilder wrapperMethodDesc = new StringBuilder();
		Type[] args = Type.getArgumentTypes(desc);
		Type retArg = Type.getReturnType(desc);
		boolean isConstructor = name.equals("<init>") ? true : false;
		boolean isStatic = opcode == Opcodes.INVOKESTATIC ? true : false;
		boolean isWhitelisted = TaintTrackerConfig.isWhitelisted(owner);
		boolean isReflectMCall = "java/lang/reflect/Method".equals(owner) && "invoke".equals(name);
		boolean isReflectCCall = "java/lang/Class".equals(owner) && "getMethod".equals(name);

		// Maps original argument position to the position with modifications
		Map<Integer, Integer> origArgs2Args = new HashMap<Integer, Integer>();
		MethodMetaInformation mmiChildMethod = TaintTrackerConfig.createMethodUtilityObject(Opcodes.ACC_PRIVATE, name,
				desc, null, null, owner);
		// Skip constructor invocations within constructors
		if (this.methodName.equals("<init>") && isConstructor) {
			mv.visitMethodInsn(opcode, owner, name, desc, false);
			return;
		}

		// Compute wrapper method description
		int posKey = 0;
		int posValue = 0;
		wrapperMethodDesc.append("(");
		if (!isStatic && !isConstructor) {
			origArgs2Args.put(posKey, posValue);
			Type tz = Type.getType(owner);
			// wrapperMethodDesc.append(Type.getDescriptor(Object.class));
			wrapperMethodDesc.append(TaintTrackerConfig.makeBCSignature(tz));
			posValue++;
			posKey++;

			Object o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - args.length - 1);
			Type objType = null;
			if (o instanceof String) {
				objType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			}

			if (TaintTrackerConfig.isString(tz)) {
				wrapperMethodDesc.append(TaintTrackerConfig.TAINT_DESC);
				posValue++;
			} else if (objType != null && TaintTrackerConfig.isString(objType)) {
				wrapperMethodDesc.append(TaintTrackerConfig.TAINT_DESC);
				posValue++;
			}
		} else if (isConstructor) {
			// posValue++;
			// posKey++;
		}
		for (Type t : args) {
			// Add space for parameter
			origArgs2Args.put(posKey, posValue);
			wrapperMethodDesc.append(t.getDescriptor());

			// check the type on the top stack entry
			Object o = (isStatic || isConstructor)
					? this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - posKey - 1)
					: this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - posKey);

			Type objType = null;
			if (o instanceof String) {
				objType = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			}

			// Add space for parameter's taint
			if (t.getSort() == Type.ARRAY && (TaintTrackerConfig.isString(t.getElementType())
					|| t.getElementType().getSort() != Type.OBJECT)) {
				wrapperMethodDesc.append(Type.getType(TaintTrackerConfig.TAINT_DESC_ARR));
				posValue++;
			} else if (t.getSort() == Type.OBJECT && TaintTrackerConfig.isString(t)) {
				wrapperMethodDesc.append(Type.getType(TaintTrackerConfig.TAINT_DESC));
				posValue++;
			} else if (t.getSort() != Type.OBJECT && t.getSort() != Type.ARRAY) {
				wrapperMethodDesc.append(Type.getType(TaintTrackerConfig.TAINT_DESC));
				posValue++;
			}
			// in case parameter type is a superclass of the stack element
			else if (objType != null && Object.class.getName().equals(TaintTrackerConfig.escapeStr(t.getInternalName()))
					&& TaintTrackerConfig.isString(objType)) {
				wrapperMethodDesc.append(Type.getType(TaintTrackerConfig.TAINT_DESC));
				posValue++;
			}
			posKey += t.getSize();
			posValue += t.getSize();
		}
		wrapperMethodDesc.append(")");

		// add return type to wrapper method description
		Type retType = Type.getReturnType(desc);
		int methodId = this.ctf.genNewMethodId();
		String wrapperMethodName = name + methodId + "WRAPPER";
		if (isConstructor) {
			Type ownerDesc = Type.getObjectType(owner);
			wrapperMethodDesc.append(ownerDesc.getDescriptor());
			wrapperMethodName = "newInit" + methodId + "Wrapper";
		} else {
			TaintWrapper<?, ?> retTypeWrapper = TaintTrackerConfig.wrapReturnType(retType);
			if (retTypeWrapper != null)
				retType = Type.getType(retTypeWrapper.getClass());
			wrapperMethodDesc.append(retType.getDescriptor());
		}

		int wrapperMethodAccess = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
		int wrapperOpcode = Opcodes.INVOKESTATIC;// Opcodes.INVOKESPECIAL;
		// boolean isParentStatic = ((this.accessFlags & Opcodes.ACC_STATIC) ==
		// Opcodes.ACC_STATIC) ? true : false;
		// if(isParentStatic){
		// wrapperMethodAccess |= Opcodes.ACC_STATIC;
		// wrapperOpcode = Opcodes.INVOKESTATIC;
		// }

		String id = this.className + "." + wrapperMethodName + ":" + wrapperMethodDesc.toString();
		if (!this.ctf.getAddedMethods().containsKey(id)) {
			this.ctf.getAddedMethods().put(id, id);

			// ----> Start: Build wrapper method
			MethodVisitor mvWrapper = cv.visitMethod(wrapperMethodAccess, wrapperMethodName,
					wrapperMethodDesc.toString(), null, null);
			mvWrapper.visitCode();

			// Push parameters on stack and invoke original method
			// use original argument list for non-whitelisted classes
			Type[] wrapperArgs = !isWhitelisted ? args : Type.getArgumentTypes(wrapperMethodDesc.toString());

			posKey = 0;// (isStatic || isConstructor) ? 0 : 1;

			if (isConstructor) {
				mvWrapper.visitTypeInsn(Opcodes.NEW, owner);
				mvWrapper.visitInsn(Opcodes.DUP);
			}
			// create a new method object with an adapted method signature for
			// reflective method calls
//			else if (isReflectMCall) {
//				mvWrapper.visitVarInsn(Opcodes.ALOAD, 0);
//				mvWrapper.visitInsn(Opcodes.DUP);
//				mvWrapper.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TaintTrackerConfig.unescapeStr(Method.class.getName()),
//						"getParameterCount", "()I", false);
//				Label skip = new Label();
//				mvWrapper.visitJumpInsn(Opcodes.IFLE, skip);
//				// mvWrapper.visitVarInsn(Opcodes.ALOAD, 0);
//				mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
//						TaintTrackerConfig.unescapeStr(ReflectionHandler.class.getName()), "adaptMethod",
//						"(Ljava/lang/reflect/Method;)Ljava/lang/reflect/Method;", false);
//				mvWrapper.visitLabel(skip);
//				posKey++;
//			}
			// do not propagate taint labels inside non-whitelisted classes
			else if (!isStatic && !isWhitelisted) {
				mvWrapper.visitVarInsn(Opcodes.ALOAD, 0);
				posKey++;
			}

			for (Type t : wrapperArgs) {
				int argsLoadOpcode = -1;
				switch (t.getSort()) {
				case Type.INT:
				case Type.SHORT:
				case Type.BYTE:
				case Type.CHAR:
					argsLoadOpcode = Opcodes.ILOAD;
					break;
				case Type.LONG:
					argsLoadOpcode = Opcodes.LLOAD;
					break;
				case Type.DOUBLE:
					argsLoadOpcode = Opcodes.DLOAD;
					break;
				case Type.FLOAT:
					argsLoadOpcode = Opcodes.FLOAD;
					break;
				case Type.OBJECT:
				case Type.ARRAY:
					argsLoadOpcode = Opcodes.ALOAD;
					break;
				}
				if (argsLoadOpcode != -1) {
					// do not propagate taint labels inside non-whitelisted
					// classes
					if (!isWhitelisted)
						mvWrapper.visitVarInsn(argsLoadOpcode, origArgs2Args.get(posKey));
					else
						mvWrapper.visitVarInsn(argsLoadOpcode, posKey);
				}
				posKey += t.getSize();
			}
//			adapt method signature and adapt taint tags for reflective class.getMethod calls
			if (isReflectCCall) {
				Object o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size()-1);
				if(o instanceof String){
//					Type t = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
					mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(ReflectionHandler.class.getName()), "adaptMethodSignature",
							"([Ljava/lang/Class;)[Ljava/lang/Class;", false);		
				}
			}
//			print parameters of a reflective call 
			if(isReflectMCall){
				Object o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size()-1);
				if(o instanceof String){
					mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(ReflectionHandler.class.getName()), "adaptMethodParameters",
							"([Ljava/lang/Object;)[Ljava/lang/Object;", false);		
				}				
			}

			// mark method invocation as sink
			// this.methodTransformerUtil.taintSink(mvWrapper, this.mmiParent,
			// mmiChildMethod);
			SinkSourceSpec isSink = this.methodTransformerUtil.isSink(mmiChildMethod);
			if (isSink != null) {
				System.out.println("Sink detected: " + isSink.getClazz() + "." + isSink.getSelector());
				String param = isSink.getParams();
				int paramPos = Integer.parseInt(param);
				if (paramPos > 0) {
					int argPos = origArgs2Args.get(paramPos);
					Type wrapperDescType = Type.getType(wrapperMethodDesc.toString());
					if (wrapperDescType.getArgumentTypes().length >= argPos) {
						int varPos = argPos + 1;
						Type taintType = wrapperDescType.getArgumentTypes()[varPos];
						if (taintType.getSort() == Type.ARRAY) {
							mvWrapper.visitVarInsn(Opcodes.ALOAD, varPos);
							mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
									TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "mergeTaints",
									"([I)I", false);
						} else if (taintType.getSort() != Type.OBJECT) {
							mvWrapper.visitVarInsn(TaintTrackerConfig.TAINT_LOAD_INSTR, varPos);
						}
						mvWrapper.visitLdcInsn(
								"Sink reached " + mmiChildMethod.getClassName() + "." + mmiChildMethod.getMethodName());
						mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC, Logger.class.getName().replace(".", "/"), "log",
								"(ILjava/lang/String;)V", false);
					}
				}
			}

			// do not propagate inside non-whitelisted methods, so take the
			// original method signature
			String newDesc = !isWhitelisted ? mmiChildMethod.getDesc() : mmiChildMethod.getNewDesc();
			Type newDescType = Type.getType(newDesc);
			Type wrapperDescType = Type.getType(wrapperMethodDesc.toString());

			// invoke the actual method
			mvWrapper.visitMethodInsn(opcode, owner, name, newDesc, itf);

			// for non-whitelisted classes propagate taint to complete object
			// if (!isWhitelisted && mmiChildMethod.getNewArgTypes().size() > 0)
			// {
			// if (opcode == Opcodes.INVOKEVIRTUAL) {
			//
			// } else if (opcode == Opcodes.INVOKESTATIC &&
			// newDescType.getReturnType().getSort() == Type.OBJECT) {
			// mvWrapper.visitInsn(Opcodes.DUP);
			// mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
			// TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
			// "addTaint",
			// "(Ljava/lang/Object;I)V", false);
			// }
			// }

			// check if method invocation is a source and add a taint
			SinkSourceSpec isSource = this.methodTransformerUtil.isSource(mmiChildMethod);
			if (isSource != null) {
				System.out.println("Source detected: " + isSource.getClazz() + "." + isSource.getSelector());
				String param = isSource.getParams();
				// the return parameter is the source
				if ("ret".equals(param)) {
					boolean returnTaintWrapper = newDescType.getReturnType().equals(wrapperDescType.getReturnType())
							&& wrapperDescType.getReturnType().getDescriptor().contains("TaintWrapper");
					if (returnTaintWrapper)
						mvWrapper.visitInsn(Opcodes.DUP);

					// return parameter is an array
					if (newDescType.getSort() == Type.ARRAY) {
						mvWrapper.visitInsn(Opcodes.DUP);
						mvWrapper.visitInsn(Opcodes.ARRAYLENGTH);
						mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
								TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "getTaint", "(I)[I",
								false);
					} else {
						mvWrapper.visitLdcInsn(this.mmiParent.getClassName());
						mvWrapper.visitLdcInsn(this.mmiParent.getMethodName());
						mvWrapper.visitLdcInsn(mmiChildMethod.getClassName());
						mvWrapper.visitLdcInsn(mmiChildMethod.getMethodName());
						mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
								TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "getTaint",
								"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I", false);
					}

					if (returnTaintWrapper) {
						// generate method descriptor for getter method
						String fieldDesc = "Ljava/lang/Object;";// retArg.getSort()
																// == Type.ARRAY
																// ?
																// TaintTrackerConfig.TAINT_DESC_ARR
																// :
																// TaintTrackerConfig.TAINT_DESC;
						mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
								TaintTrackerConfig.unescapeStr(Integer.class.getName()), "valueOf",
								"(I)Ljava/lang/Integer;", false);
						mvWrapper.visitFieldInsn(Opcodes.PUTFIELD,
								TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "taint", fieldDesc);
					}
				}
				// maybe one o the methods parameters is declared as a source
				else {
					int paramPos = Integer.parseInt(param);
					if (paramPos > 0) {
						int argPos = origArgs2Args.get(paramPos);
						if (wrapperDescType.getArgumentTypes().length >= argPos) {
							int varPos = argPos + 1;// TODO: distinguish between
													// static and instance
													// method invocation
							Type taintType = wrapperDescType.getArgumentTypes()[varPos];
							if (taintType.getSort() == Type.ARRAY) {
								mvWrapper.visitVarInsn(Opcodes.ALOAD, varPos);
								mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
										TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "getTaint",
										"([I)V", false);
								// print message on commandline
								mvWrapper.visitVarInsn(Opcodes.ALOAD, varPos);
								mvWrapper.visitInsn(Opcodes.ICONST_0);
								mvWrapper.visitInsn(Opcodes.IALOAD);
								mvWrapper.visitLdcInsn("Source invoked " + mmiChildMethod.getClassName() + "."
										+ mmiChildMethod.getMethodName());
								mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
										Logger.class.getName().replace(".", "/"), "log", "(ILjava/lang/String;)V",
										false);
							} else if (taintType.getSort() != Type.OBJECT || TaintTrackerConfig.isString(taintType)) {
								mvWrapper.visitLdcInsn(this.mmiParent.getClassName());
								mvWrapper.visitLdcInsn(this.mmiParent.getMethodName());
								mvWrapper.visitLdcInsn(mmiChildMethod.getClassName());
								mvWrapper.visitLdcInsn(mmiChildMethod.getMethodName());
								mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
										TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()), "getTaint",
										"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
										false);
							}
						}
					}
				}
			}
			
//			merge all taint labels if its not a source nor a sink
			if(isSource == null && isSink == null){
				//TODO: is method invocation is not a source and not a sink then merge all taint marks of passed parameters and them to the object and possibly returned value
			}

			// add return statement at the end of method
			if (isConstructor) {
				mvWrapper.visitInsn(Opcodes.ARETURN);
			} else if (retArg.getSort() == Type.VOID) {
				mvWrapper.visitInsn(Opcode.RETURN);
			} else if (retArg.getSort() == Type.OBJECT && !TaintTrackerConfig.isString(retArg)) {
				mvWrapper.visitInsn(Opcodes.ARETURN);
			} else if (retArg.getSort() == Type.ARRAY && !TaintTrackerConfig.isString(retArg.getElementType())) {
				mvWrapper.visitInsn(Opcodes.ARETURN);
			} else {
				if (!newDescType.getReturnType().equals(wrapperDescType.getReturnType())
						&& wrapperDescType.getReturnType().getDescriptor().contains("TaintWrapper")) {
					// determine taint size
					String fieldName = "EMPTY_TAINT";
					String fieldDesc = TaintTrackerConfig.TAINT_DESC;

					// load empty taint on stack if method invocation is not a
					// source
					if (retArg.getSort() == Type.ARRAY) {
						fieldName = "EMPTY_ARR_TAINT";
						fieldDesc = TaintTrackerConfig.TAINT_DESC_ARR;
						mvWrapper.visitInsn(Opcodes.DUP);
						mvWrapper.visitInsn(Opcodes.ARRAYLENGTH);
						mvWrapper.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT);
					} else {
						// mvWrapper.visitFieldInsn(Opcodes.GETSTATIC,
						// TaintTrackerConfig.unescapeStr(TaintTrackerConfig.class.getName()),
						// fieldName,
						// fieldDesc);
						mvWrapper.visitInsn(TaintTrackerConfig.EMPTY_TAINT);
					}

					// generate method descriptor for getter method
					String getWrapperDesc = "(" + retArg.getDescriptor() + fieldDesc + ")" + TaintTrackerConfig
							.makeBCSignature(TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()));
					mvWrapper.visitMethodInsn(Opcodes.INVOKESTATIC,
							TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()), "getWrapper", getWrapperDesc,
							false);
				}
				mvWrapper.visitInsn(Opcodes.ARETURN);
			}

			mvWrapper.visitMaxs(wrapperMethodDesc.length() + 1, wrapperMethodDesc.length() + 1);
			mvWrapper.visitEnd();
			// ----> End: Build wrapper method
		}

		// invoke wrapped method and unfold return value if necessary
		Type wrapperClassType = Type.getType(TaintTrackerConfig.unescapeStr(this.className));
		Type wrapperReturnType = Type.getReturnType(wrapperMethodDesc.toString());
		// mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, name, desc, intf);

//		if (isReflectMCall) {
//			// M-o-P
//			mv.visitInsn(Opcode.DUP2_X1);
//			// O-P-M-O-P
//			mv.visitInsn(Opcodes.POP2);
//			// O-P-M
//			mv.visitInsn(Opcodes.DUP_X2);
//			// M-O-P-M
//			mv.visitMethodInsn(Opcodes.INVOKESTATIC, Logger.class.getName().replace(".", "/"), "log",
//					"(Ljava/lang/reflect/Method;)V", false);
//		}
		mv.visitMethodInsn(wrapperOpcode, wrapperClassType.getDescriptor(), wrapperMethodName,
				wrapperMethodDesc.toString(), itf);

		// top two entries contain old and new reference object, remove old
		// reference by swap and pop execution
		if (isConstructor) {
			mv.visitInsn(Opcodes.SWAP);
			mv.visitInsn(Opcodes.POP);
			mv.visitInsn(Opcodes.SWAP);
			mv.visitInsn(Opcodes.POP);

			// for non-whitelisted objects we store the taint marks in a
			// separated hash-table,
			// whitelisted objects instead have a special taint attribute, see
			// classvisitor->end()
			if (TaintTrackerConfig.isWhitelisted(owner)) {
				mv.visitInsn(Opcodes.DUP);
				mv.visitMethodInsn(Opcodes.INVOKESTATIC, TaintTrackerConfig.unescapeStr(RuntimeTracker.class.getName()),
						"newTaint", "(Ljava/lang/Object;)V", false);
			}
		}
		// unfold return value if it is typed TaintWrapper
		// else if (wrapperReturnType.getSort() != Type.VOID &&
		// wrapperReturnType.getSort() == Type.OBJECT) {
		else if ((wrapperReturnType.getSort() == Type.OBJECT || wrapperReturnType.getSort() == Type.ARRAY)
				&& (wrapperReturnType.getInternalName().equals(TaintWrapper.class.getName().replace(".", "/")))) {
			this.methodTransformerUtil.unfoldWrapperValue(mv, Type.getReturnType(desc));
		} else if (isReflectMCall) {
			Object o = this.analyzerAdapter.stack.get(this.analyzerAdapter.stack.size() - 2);
			if (o instanceof String) {
				Type t = Type.getType(TaintTrackerConfig.makeBCSignature((String) o));
			}
			mv.visitInsn(Opcodes.DUP);
			mv.visitTypeInsn(Opcodes.INSTANCEOF, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()));
			Label noInstLab = new Label();
			mv.visitJumpInsn(Opcodes.IFEQ, noInstLab);
			mv.visitTypeInsn(Opcodes.CHECKCAST, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()));
			mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, TaintTrackerConfig.unescapeStr(TaintWrapper.class.getName()),
					"getValueAsWrapper", "()Ljava/lang/Object;", false);
			mv.visitLabel(noInstLab);
		}
	}

	@Override
	public void visitMaxs(int maxStack, int maxLocals) {
		int offset = this.methodTransformerUtil.getLocalVar2Tmp().size()
				+ this.methodTransformerUtil.getLocalVar2Shadow().size();
		mv.visitMaxs(maxStack + offset, maxLocals + offset);
	}

	@Override
	public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
		mv.visitTryCatchBlock(start, end, handler, type);
	}

	@Override
	public void visitEnd() {
		// this.lvm.visitEnd();
		if (!this.methodTransformerUtil.visitedLabelEnd) {
			mv.visitLabel(this.methodTransformerUtil.endLabel);
			this.methodTransformerUtil.visitedLabelEnd = true;
		}
		Map<Integer, LocalVariableNode> map;
		// add taint variables to local variable table
		if (this.methodTransformerUtil.getLocalVar2Shadow().size() > 0) {
			map = this.methodTransformerUtil.getLocalVar2Shadow();
			for (int key : map.keySet()) {
				LocalVariableNode n = map.get(key);
				mv.visitLocalVariable(n.name, n.desc, n.signature, n.start.getLabel(), n.end.getLabel(), n.index);
			}
			map.clear();
		}
		// add temporary variables to local variable table
		if (this.methodTransformerUtil.getLocalVar2Tmp().size() > 0) {
			map = this.methodTransformerUtil.getLocalVar2Tmp();
			for (int key : map.keySet()) {
				LocalVariableNode n = map.get(key);
				mv.visitLocalVariable(n.name, n.desc, n.signature, n.start.getLabel(), n.end.getLabel(), n.index);
			}
			map.clear();
		}
		mv.visitEnd();
	}

	/*
	 * @Override public void visitFrame(int type, int nLocal, Object[] local,
	 * int nStack, Object[] stack) { super.visitFrame(type, nLocal, local,
	 * nStack, stack); }
	 */

	/*
	 * public AnnotationVisitor visitLocalVariableAnnotation(int typeRef,
	 * TypePath typePath, Label[] start, Label[] end, int[] index, String desc,
	 * boolean visible) { return mv.visitLocalVariableAnnotation(typeRef,
	 * typePath, start, end, index, desc, visible); }
	 */

	/*
	 * @Override public void visitLocalVariable(String name, String desc, String
	 * signature, Label start, Label end, int index) {
	 * mv.visitLocalVariable(name, desc, signature, start, end, index); }
	 */
}
