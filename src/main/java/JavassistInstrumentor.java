import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.List;

import org.objectweb.asm.Opcodes;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import javassist.bytecode.BadBytecode;
import javassist.bytecode.Bytecode;
import javassist.bytecode.ClassFile;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.FieldInfo;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Mnemonic;
import javassist.bytecode.Opcode;


public class JavassistInstrumentor {
	
	public static void main(String[] args){
		 int target = 0x0002;
		 target = target & ~Opcodes.ACC_FINAL;
		 target = target & ~Opcodes.ACC_PRIVATE;
		 target = target & ~Opcodes.ACC_PROTECTED;
		 target = target | Opcodes.ACC_PUBLIC;
			
		 System.out.println(Integer.toBinaryString(target));
	}
	
	public void instrument(String p_classname){
		try {
			ClassPool clPool = ClassPool.getDefault();
			CtClass cc = clPool.get(p_classname);
//			cc.writeFile("jzip2.jzip");
			ClassFile cf = new ClassFile(new DataInputStream(new ByteArrayInputStream(cc.toBytecode())));
			List<FieldInfo> fields = cf.getFields();
			FieldInfo myattr = new FieldInfo(cf.getConstPool(), "myattr", "I");
			for(int i = 0; i < fields.size(); i++){
				FieldInfo fi = fields.get(i);
				System.out.println("FieldInfo: "+fi.getName()+", "+fi.getDescriptor()+", "+Integer.toBinaryString(fi.getAccessFlags()));
				if(i==0)
				cf.addField(myattr);
			}
			Bytecode b = new Bytecode(cf.getConstPool(), 1, 5);
			b.addIconst(3);
			b.addOpcode(Opcode.POP);
			
			MethodInfo mi = cf.getMethod("zipIt");
			ConstPool cp = mi.getConstPool();
			CodeAttribute ca = mi.getCodeAttribute();
			CodeIterator ci = ca.iterator();
			ci.append(b.toCodeAttribute().getCode());
			while(ci.hasNext()){
				int index = ci.next();
				System.out.println(index+", "+Mnemonic.OPCODE[ci.byteAt(index)]);
				if(Mnemonic.OPCODE[ci.byteAt(index)].equals("invokevirtual")){
					int cpindex = ci.s16bitAt(index +1);
//					System.out.println(index+", "+Mnemonic.OPCODE[ci.byteAt(index)]+", "+cp.getMethodrefClassName(cpindex)+", "+cp.getMethodrefName(cpindex));
				}
			}
		} catch (NotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CannotCompileException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadBytecode e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
