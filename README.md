# gdbproxy

Simple proxy for the GDB server protocol.

```lua
% uv run gdbproxy -l localhost:4321 -s localhost:23946
GDB proxy listening on 127.0.0.1:4321
Forwarding to localhost:23946

[13:48:22.7254 Session 1 started: server(localhost:23946) <-> client(::1:52151)
[13:48:22.7255   <-- +
           ACK
[13:48:22.7257   <-- $qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;error-message+#14
           Query supported features: multiprocess+, swbreak+, hwbreak+, qRelocInsn+, fork-events+, vfork-events+, exec-events+, vContSupported+, QThreadEvents+, QThreadOptions+, no-resumed+, memory-tagging+, xmlRegisters=i386, error-message+
[13:48:22.7264   --> +
           ACK
[13:48:22.7269   --> $PacketSize=1000;vContSupported+;multiprocess+;QStartNoAckMode+;fork-events+;vfork-events+;vforkdone-events+;swbreak+;hwbreak+;qXfer:features:read+;qXfer:libraries:read+#a0
           Features: PacketSize=1000, vContSupported+, multiprocess+, QStartNoAckMode+, fork-events+, vfork-events+, vforkdone-events+, swbreak+, hwbreak+, qXfer=features:read+, qXfer=libraries:read+
[13:48:22.7271   <-- +
           ACK
[13:48:22.7271   <-- $vCont?#49
           Query vCont support
[13:48:22.7273   --> +
           ACK
[13:48:22.7274   --> $vCont;c;C;s;S#62
           vCont supported: continue, continue with signal, step, step with signal
[13:48:22.7275   <-- +
           ACK
[13:48:22.7275   <-- $vMustReplyEmpty#3a
           Must reply empty (probe)
[13:48:22.7277   --> +
           ACK
[13:48:22.7277   --> $#00
           Empty packet
[13:48:22.7278   <-- +
           ACK
[13:48:22.7279   <-- $QStartNoAckMode#b0
           Enable no-ack mode
[13:48:22.7280   --> +
           ACK
[13:48:22.7281   --> $OK#9a
           OK
[13:48:22.7282   <-- +
           ACK
[13:48:22.7282   <-- $Hgp0.0#ad
           Set thread for general ops: p0.0
[13:48:22.7283   --> $OK#9a
           OK
[13:48:22.7285   <-- $qXfer:features:read:target.xml:0,ffb#79
           Read target features:target.xml (offset=0x0, len=0xffb)
[13:48:22.7290   --> $m<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
  <architecture>i386:x86-64</architecture>
  <xi:include href="64bit-core.xml"/>
  <xi:include href="64bit-sse.xml"/>
</target>
#95
           XML data (partial): <target> (201 bytes)
[13:48:22.7294   <-- $qXfer:features:read:target.xml:c9,ffb#e5
           Read target features:target.xml (offset=0xc9, len=0xffb)
[13:48:22.7295   --> $l#6c
           End of list
[13:48:22.7296   <-- $qXfer:features:read:64bit-core.xml:0,ffb#71
           Read target features:64bit-core.xml (offset=0x0, len=0xffb)
[13:48:22.7313   --> $m<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<feature name="org.gnu.gdb.i386.core">
  <flags id="i386_eflags" size="4">
 * <field name="CF" start="0" end="0"/>
 * <field name="" start="1" end="1"/>
 * <field name="PF" start="2" end="2"/>
 * <field name="AF" start="4" end="4"/>
 * <field name="ZF" start="6" end="6"/>
 * <field name="SF" start="7" end="7"/>
 * <field name="TF" start="8" end="8"/>
 * <field name="IF" start="9" end="9"/>
 * <field name="DF" start="10" end="10"/>
 * <field name="OF" start="11" end="11"/>
 * <field name="NT" start="14" end="14"/>
 * <field name="RF" start="16" end="16"/>
 * <field name="VM" start="17" end="17"/>
 * <field name="AC" start="18" end="18"/>
 * <field name="VIF" start="19" end="19"/>
 * <field name="VIP" start="20" end="20"/>
 * <field name="ID" start="21" end="21"/>
  </flags>

  <reg name="rax" bitsize="64" type="int64"/>
  <reg name="rbx" bitsize="64" type="int64"/>
  <reg name="rcx" bitsize="64" type="int64"/>
  <reg name="rdx" bitsize="64" type="int64"/>
  <reg name="rsi" bitsize="64" type="int64"/>
  <reg name="rdi" bitsize="64" type="int64"/>
  <reg name="rbp" bitsize="64" type="data_ptr"/>
  <reg name="rsp" bitsize="64" type="data_ptr"/>
  <reg name="r8" bitsize="64" type="int64"/>
  <reg name="r9" bitsize="64" type="int64"/>
  <reg name="r10" bitsize="64" type="int64"/>
  <reg name="r11" bitsize="64" type="int64"/>
  <reg name="r12" bitsize="64" type="int64"/>
  <reg name="r13" bitsize="64" type="int64"/>
  <reg name="r14" bitsize="64" type="int64"/>
  <reg name="r15" bitsize="64" type="int64"/>

  <reg name="rip" bitsize="64" type="code_ptr"/>
  <reg name="eflags" bitsize="32" type="i386_eflags"/>
  <reg name="cs" bitsize="32" type="int32"/>
  <reg name="ss" bitsize="32" type="int32"/>
  <reg name="ds" bitsize="32" type="int32"/>
  <reg name="es" bitsize="32" type="int32"/>
  <reg name="fs" bitsize="32" type="int32"/>
  <reg name="gs" bitsize="32" type="int32"/>

  <reg name="st0" bitsize="80" type="i387_ext"/>
  <reg name="st1" bitsize="80" type="i387_ext"/>
  <reg name="st2" bitsize="80" type="i387_ext"/>
  <reg name="st3" bitsize="80" type="i387_ext"/>
  <reg name="st4" bitsize="80" type="i387_ext"/>
  <reg name="st5" bitsize="80" type="i387_ext"/>
  <reg name="st6" bitsize="80" type="i387_ext"/>
  <reg name="st7" bitsize="80" type="i387_ext"/>

  <reg name="fctrl" bitsize="32" type="int" group="float"/>
  <reg name="fstat" bitsize="32" type="int" group="float"/>
  <reg name="ftag" bitsize="32" type="int" group="float"/>
  <reg name="fiseg" bitsize="32" type="int" group="float"/>
  <reg name="fioff" bitsize="32" type="int" group="float"/>
  <reg name="foseg" bitsize="32" type="int" group="float"/>
  <reg name="fooff" bitsize="32" type="int" group="float"/>
  <reg name="fop" bitsize="32" type="int" group="float"/>
</feature>
#74
           XML data (partial): <feature> (2847 bytes)
[13:48:22.7315   <-- $qXfer:features:read:64bit-core.xml:b30,ffb#06
           Read target features:64bit-core.xml (offset=0xb30, len=0xffb)
[13:48:22.7316   --> $l#6c
           End of list
[13:48:22.7318   <-- $qXfer:features:read:64bit-sse.xml:0,ffb#13
           Read target features:64bit-sse.xml (offset=0x0, len=0xffb)
[13:48:22.7331   --> $m<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<feature name="org.gnu.gdb.i386.sse">
  <vector id="v4f" type="ieee_single" count="4"/>
  <vector id="v2d" type="ieee_double" count="2"/>
  <vector id="v16i8" type="int8" count="16"/>
  <vector id="v8i16" type="int16" count="8"/>
  <vector id="v4i32" type="int32" count="4"/>
  <vector id="v2i64" type="int64" count="2"/>
  <union id="vec128">
 * <field name="v4_float" type="v4f"/>
 * <field name="v2_double" type="v2d"/>
 * <field name="v16_int8" type="v16i8"/>
 * <field name="v8_int16" type="v8i16"/>
 * <field name="v4_int32" type="v4i32"/>
 * <field name="v2_int64" type="v2i64"/>
 * <field name="uint128" type="uint128"/>
  </union>
  <flags id="i386_mxcsr" size="4">
 * <field name="IE" start="0" end="0"/>
 * <field name="DE" start="1" end="1"/>
 * <field name="ZE" start="2" end="2"/>
 * <field name="OE" start="3" end="3"/>
 * <field name="UE" start="4" end="4"/>
 * <field name="PE" start="5" end="5"/>
 * <field name="DAZ" start="6" end="6"/>
 * <field name="IM" start="7" end="7"/>
 * <field name="DM" start="8" end="8"/>
 * <field name="ZM" start="9" end="9"/>
 * <field name="OM" start="10" end="10"/>
 * <field name="UM" start="11" end="11"/>
 * <field name="PM" start="12" end="12"/>
 * <field name="FZ" start="15" end="15"/>
  </flags>

  <reg name="xmm0" bitsize="128" type="vec128" regnum="40"/>
  <reg name="xmm1" bitsize="128" type="vec128"/>
  <reg name="xmm2" bitsize="128" type="vec128"/>
  <reg name="xmm3" bitsize="128" type="vec128"/>
  <reg name="xmm4" bitsize="128" type="vec128"/>
  <reg name="xmm5" bitsize="128" type="vec128"/>
  <reg name="xmm6" bitsize="128" type="vec128"/>
  <reg name="xmm7" bitsize="128" type="vec128"/>
  <reg name="xmm8" bitsize="128" type="vec128"/>
  <reg name="xmm9" bitsize="128" type="vec128"/>
  <reg name="xmm10" bitsize="128" type="vec128"/>
  <reg name="xmm11" bitsize="128" type="vec128"/>
  <reg name="xmm12" bitsize="128" type="vec128"/>
  <reg name="xmm13" bitsize="128" type="vec128"/>
  <reg name="xmm14" bitsize="128" type="vec128"/>
  <reg name="xmm15" bitsize="128" type="vec128"/>

  <reg name="mxcsr" bitsize="32" type="i386_mxcsr" group="vector"/>
</feature>
#97
           XML data (partial): <feature> (2203 bytes)
[13:48:22.7333   <-- $qXfer:features:read:64bit-sse.xml:8b0,ffb#ad
           Read target features:64bit-sse.xml (offset=0x8b0, len=0xffb)
[13:48:22.7335   --> $l#6c
           End of list
[13:48:22.7338   <-- $qTStatus#49
           Query trace status
[13:48:22.7340   --> $#00
           Empty packet
[13:48:22.7341   <-- $?#3f
           Query halt reason
[13:48:22.7342   --> $T05thread:p01.01;library:;#70
           Stopped: SIGTRAP (thread:p01.01;library:;)
[13:48:22.7343   <-- $qfThreadInfo#bb
           Query first thread info
[13:48:22.7344   --> $mp01.01#cd
           Thread: p01.01
[13:48:22.7345   <-- $qsThreadInfo#c8
           Query next thread info
[13:48:22.7346   --> $l#6c
           End of list
[13:48:22.7347   <-- $qAttached:1#fa
           Query if attached to process 1
[13:48:22.7349   --> $1#31
           Data: 1
[13:48:22.7350   <-- $qXfer:features:read:target.xml:0,ffb#79
           Read target features:target.xml (offset=0x0, len=0xffb)
[13:48:22.7353   --> $m<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
  <architecture>i386:x86-64</architecture>
  <xi:include href="64bit-core.xml"/>
  <xi:include href="64bit-sse.xml"/>
</target>
#95
           XML data (partial): <target> (201 bytes)
[13:48:22.7354   <-- $qXfer:features:read:target.xml:c9,ffb#e5
           Read target features:target.xml (offset=0xc9, len=0xffb)
[13:48:22.7355   --> $l#6c
           End of list
[13:48:22.7356   <-- $qXfer:features:read:64bit-core.xml:0,ffb#71
           Read target features:64bit-core.xml (offset=0x0, len=0xffb)
[13:48:22.7373   --> $m<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<feature name="org.gnu.gdb.i386.core">
  <flags id="i386_eflags" size="4">
 * <field name="CF" start="0" end="0"/>
 * <field name="" start="1" end="1"/>
 * <field name="PF" start="2" end="2"/>
 * <field name="AF" start="4" end="4"/>
 * <field name="ZF" start="6" end="6"/>
 * <field name="SF" start="7" end="7"/>
 * <field name="TF" start="8" end="8"/>
 * <field name="IF" start="9" end="9"/>
 * <field name="DF" start="10" end="10"/>
 * <field name="OF" start="11" end="11"/>
 * <field name="NT" start="14" end="14"/>
 * <field name="RF" start="16" end="16"/>
 * <field name="VM" start="17" end="17"/>
 * <field name="AC" start="18" end="18"/>
 * <field name="VIF" start="19" end="19"/>
 * <field name="VIP" start="20" end="20"/>
 * <field name="ID" start="21" end="21"/>
  </flags>

  <reg name="rax" bitsize="64" type="int64"/>
  <reg name="rbx" bitsize="64" type="int64"/>
  <reg name="rcx" bitsize="64" type="int64"/>
  <reg name="rdx" bitsize="64" type="int64"/>
  <reg name="rsi" bitsize="64" type="int64"/>
  <reg name="rdi" bitsize="64" type="int64"/>
  <reg name="rbp" bitsize="64" type="data_ptr"/>
  <reg name="rsp" bitsize="64" type="data_ptr"/>
  <reg name="r8" bitsize="64" type="int64"/>
  <reg name="r9" bitsize="64" type="int64"/>
  <reg name="r10" bitsize="64" type="int64"/>
  <reg name="r11" bitsize="64" type="int64"/>
  <reg name="r12" bitsize="64" type="int64"/>
  <reg name="r13" bitsize="64" type="int64"/>
  <reg name="r14" bitsize="64" type="int64"/>
  <reg name="r15" bitsize="64" type="int64"/>

  <reg name="rip" bitsize="64" type="code_ptr"/>
  <reg name="eflags" bitsize="32" type="i386_eflags"/>
  <reg name="cs" bitsize="32" type="int32"/>
  <reg name="ss" bitsize="32" type="int32"/>
  <reg name="ds" bitsize="32" type="int32"/>
  <reg name="es" bitsize="32" type="int32"/>
  <reg name="fs" bitsize="32" type="int32"/>
  <reg name="gs" bitsize="32" type="int32"/>

  <reg name="st0" bitsize="80" type="i387_ext"/>
  <reg name="st1" bitsize="80" type="i387_ext"/>
  <reg name="st2" bitsize="80" type="i387_ext"/>
  <reg name="st3" bitsize="80" type="i387_ext"/>
  <reg name="st4" bitsize="80" type="i387_ext"/>
  <reg name="st5" bitsize="80" type="i387_ext"/>
  <reg name="st6" bitsize="80" type="i387_ext"/>
  <reg name="st7" bitsize="80" type="i387_ext"/>

  <reg name="fctrl" bitsize="32" type="int" group="float"/>
  <reg name="fstat" bitsize="32" type="int" group="float"/>
  <reg name="ftag" bitsize="32" type="int" group="float"/>
  <reg name="fiseg" bitsize="32" type="int" group="float"/>
  <reg name="fioff" bitsize="32" type="int" group="float"/>
  <reg name="foseg" bitsize="32" type="int" group="float"/>
  <reg name="fooff" bitsize="32" type="int" group="float"/>
  <reg name="fop" bitsize="32" type="int" group="float"/>
</feature>
#74
           XML data (partial): <feature> (2847 bytes)
[13:48:22.7375   <-- $qXfer:features:read:64bit-core.xml:b30,ffb#06
           Read target features:64bit-core.xml (offset=0xb30, len=0xffb)
[13:48:22.7377   --> $l#6c
           End of list
[13:48:22.7378   <-- $qXfer:features:read:64bit-sse.xml:0,ffb#13
           Read target features:64bit-sse.xml (offset=0x0, len=0xffb)
[13:48:22.7390   --> $m<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<feature name="org.gnu.gdb.i386.sse">
  <vector id="v4f" type="ieee_single" count="4"/>
  <vector id="v2d" type="ieee_double" count="2"/>
  <vector id="v16i8" type="int8" count="16"/>
  <vector id="v8i16" type="int16" count="8"/>
  <vector id="v4i32" type="int32" count="4"/>
  <vector id="v2i64" type="int64" count="2"/>
  <union id="vec128">
 * <field name="v4_float" type="v4f"/>
 * <field name="v2_double" type="v2d"/>
 * <field name="v16_int8" type="v16i8"/>
 * <field name="v8_int16" type="v8i16"/>
 * <field name="v4_int32" type="v4i32"/>
 * <field name="v2_int64" type="v2i64"/>
 * <field name="uint128" type="uint128"/>
  </union>
  <flags id="i386_mxcsr" size="4">
 * <field name="IE" start="0" end="0"/>
 * <field name="DE" start="1" end="1"/>
 * <field name="ZE" start="2" end="2"/>
 * <field name="OE" start="3" end="3"/>
 * <field name="UE" start="4" end="4"/>
 * <field name="PE" start="5" end="5"/>
 * <field name="DAZ" start="6" end="6"/>
 * <field name="IM" start="7" end="7"/>
 * <field name="DM" start="8" end="8"/>
 * <field name="ZM" start="9" end="9"/>
 * <field name="OM" start="10" end="10"/>
 * <field name="UM" start="11" end="11"/>
 * <field name="PM" start="12" end="12"/>
 * <field name="FZ" start="15" end="15"/>
  </flags>

  <reg name="xmm0" bitsize="128" type="vec128" regnum="40"/>
  <reg name="xmm1" bitsize="128" type="vec128"/>
  <reg name="xmm2" bitsize="128" type="vec128"/>
  <reg name="xmm3" bitsize="128" type="vec128"/>
  <reg name="xmm4" bitsize="128" type="vec128"/>
  <reg name="xmm5" bitsize="128" type="vec128"/>
  <reg name="xmm6" bitsize="128" type="vec128"/>
  <reg name="xmm7" bitsize="128" type="vec128"/>
  <reg name="xmm8" bitsize="128" type="vec128"/>
  <reg name="xmm9" bitsize="128" type="vec128"/>
  <reg name="xmm10" bitsize="128" type="vec128"/>
  <reg name="xmm11" bitsize="128" type="vec128"/>
  <reg name="xmm12" bitsize="128" type="vec128"/>
  <reg name="xmm13" bitsize="128" type="vec128"/>
  <reg name="xmm14" bitsize="128" type="vec128"/>
  <reg name="xmm15" bitsize="128" type="vec128"/>

  <reg name="mxcsr" bitsize="32" type="i386_mxcsr" group="vector"/>
</feature>
#97
           XML data (partial): <feature> (2203 bytes)
[13:48:22.7391   <-- $qXfer:features:read:64bit-sse.xml:8b0,ffb#ad
           Read target features:64bit-sse.xml (offset=0x8b0, len=0xffb)
[13:48:22.7393   --> $l#6c
           End of list
[13:48:22.7394   <-- $Hc-1#09
           Set thread for continue ops: all threads
[13:48:22.7395   --> $OK#9a
           OK
[13:48:22.7396   <-- $g#67
           Read all registers
[13:48:22.7399   --> $0*~b0320*(a0320*~0*Df013004001000*!200*!3300*!2b00*!2b00*!2b00*!5300*!2b0*~0*`7f020*(f* 0*~0*~0*~0*~0*~0*f#c4
           Response: 0*~b0320*(a0320*~0*Df013004001000*!200*!3300*!2b00*!2b00*!2b00*!5300*!2b0*~0*`7f020*(f* 0*~0*~0*~0*~0*~0*f
[13:48:22.7400   <-- $qfThreadInfo#bb
           Query first thread info
[13:48:22.7401   --> $mp01.01#cd
           Thread: p01.01
[13:48:22.7402   <-- $qsThreadInfo#c8
           Query next thread info
[13:48:22.7403   --> $l#6c
           End of list
```