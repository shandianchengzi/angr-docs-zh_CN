速查表
==========

以下速查表旨在概述你可以使用 angr 做的各种事情，并作为快速参考，以便在不必深入查阅详细文档的情况下检查某些语法。

通用入门
-----------------------

一些有用的 import

.. code-block:: python

   import angr #the main framework
   import claripy #the solver engine

加载二进制文件

.. code-block:: python

   proj = angr.Project("/path/to/binary", auto_load_libs=False) # auto_load_libs False for improved performance

States
------

创建 SimState 对象

.. code-block:: python

   state = proj.factory.entry_state()

Simulation Managers
-------------------

创建 simulation manager 对象

.. code-block:: python

   simgr = proj.factory.simulation_manager(state)

探索和分析 States
------------------------------

选择不同的 explore 策略

.. code-block:: python

   simgr.use_technique(angr.exploration_techniques.DFS())

Symbolically execute until we find a state satisfying our ``find=`` and ``avoid=`` parameters

.. code-block:: python

   avoid_addr = [0x400c06, 0x400bc7]
   find_addr = 0x400c10d
   simgr.explore(find=find_addr, avoid=avoid_addr)

.. code-block:: python

   found = simgr.found[0] # A state that reached the find condition from explore
   found.solver.eval(sym_arg, cast_to=bytes) # Return a concrete string value for the sym arg to reach this state

符号执行直到 lambda 表达式为 ``True``

.. code-block:: python

   simgr.step(until=lambda sm: sm.active[0].addr >= first_jmp)

以下代码在能够访问当前的 STDOUT 或 STDERR 时特别有用（这里的 1 是 STDOUT 的文件描述符）

.. code-block:: python

   simgr.explore(find=lambda s: "correct" in s.posix.dumps(1))

大规模搜索中的内存管理（自动丢弃 Stashes）：

.. code-block:: python


   simgr.explore(find=find_addr, avoid=avoid_addr, step_func=lambda lsm: lsm.drop(stash='avoid'))

手动 explore
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   simgr.step(step_func=step_func, until=lambda lsm: len(sm.found) > 0)

   def step_func(lsm):
       lsm.stash(filter_func=lambda state: state.addr == 0x400c06, from_stash='active', to_stash='avoid')
       lsm.stash(filter_func=lambda state: state.addr == 0x400bc7, from_stash='active', to_stash='avoid')
       lsm.stash(filter_func=lambda state: state.addr == 0x400c10, from_stash='active', to_stash='found')
       return lsm

启用 Simulation Manager 的日志输出：

.. code-block:: python

   import logging
   logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

存储的内容（Stashes）
^^^^^^^

移动 Stash:

.. code-block:: python

   simgr.stash(from_stash="found", to_stash="active")

丢弃 Stashes:

.. code-block:: python

   simgr.drop(stash="avoid")

约束求解器 (claripy)
---------------------------

创建符号化对象

.. code-block:: python

   sym_arg_size = 15 #Length in Bytes because we will multiply with 8 later
   sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)

将符号参数限制在某种 char 范围内

.. code-block:: python

   for byte in sym_arg.chop(8):
       initial_state.add_constraints(byte >= '\x20') # ' '
       initial_state.add_constraints(byte <= '\x7e') # '~'

创建带有符号参数的状态

.. code-block:: python

   argv = [proj.filename]
   argv.append(sym_arg)
   state = proj.factory.entry_state(args=argv)

使用参数进行求解:

.. code-block:: python

   sym_arg = angr.claripy.BVS("sym_arg", flag_size * 8)
   argv = [proj.filename]
   argv.append(sym_arg)
   initial_state = proj.factory.full_init_state(args=argv, add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})

FFI 和 Hooking
---------------

从 ipython 调用函数

.. code-block:: python

   f = proj.factory.callable(address)
   f(10)
   x=claripy.BVS('x', 64)
   f(x) #TODO: Find out how to make that result readable

如果你感兴趣的内容没有直接返回，例如函数返回的是指向缓冲区的指针，你可以用以下代码访问函数返回后的状态

.. code-block:: python

   >>> f.result_state
   <SimState @ 0x1000550>

Hooking

已经为 libc 函数预定义了 Hook 函数（对于静态编译的库很有用）

.. code-block:: python

   proj = angr.Project('/path/to/binary', use_sim_procedures=True)
   proj.hook(addr, angr.SIM_PROCEDURES['libc']['atoi']())

使用 Simprocedure 进行 Hook：

.. code-block:: python

   class fixpid(angr.SimProcedure):
       def run(self):
               return 0x30

   proj.hook(0x4008cd, fixpid())

其他有用的技巧
-------------------

如果收到 ctr+c，则进入 ipython（对于调试运行时间过长的脚本非常有用）

.. code-block:: python

   import signal
   def killmyself():
       os.system('kill %d' % os.getpid())
   def sigint_handler(signum, frame):
       print 'Stopping Execution for Debug. If you want to kill the program issue: killmyself()'
       if not "IPython" in sys.modules:
           import IPython
           IPython.embed()

   signal.signal(signal.SIGINT, sigint_handler)

获取状态的 calltrace 以找出我们卡住的位置

.. code-block:: python

   state = simgr.active[0]
   print state.callstack

获取 basic block

.. code-block:: python

   block = proj.factory.block(address)
   block.capstone.pp() # Capstone object has pretty print and other data about the disassembly
   block.vex.pp()      # Print vex representation

State 操作
------------------

向 state 写内存:

.. code-block:: python

   aaaa = claripy.BVV(0x41414141, 32) # 32 = Bits
   state.memory.store(0x6021f2, aaaa)

读取帧内容赋值给另一个指针:

.. code-block:: python

   poi1 = new_state.solver.eval(new_state.regs.rbp)-0x10
   poi1 = new_state.mem[poi1].long.concrete
   poi1 += 0x8
   ptr1 = new_state.mem[poi1].long.concrete

从 State 读内存:

.. code-block:: python

   key = []
   for i in range(38):
       key.append(extractkey.mem[0x602140 + i*4].int.concrete)

或者，下面的表达式是等价的

.. code-block:: python

   key = extractkey.mem[0x602140].int.array(38).concrete

调试 angr
--------------

在每次内存读/写时设置断点：

.. code-block:: python

   new_state.inspect.b('mem_read', when=angr.BP_AFTER, action=debug_funcRead)
   def debug_funcRead(state):
       print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address

在特定内存位置设置断点：

.. code-block:: python

   new_state.inspect.b('mem_write', mem_write_address=0x6021f1, when=angr.BP_AFTER, action=debug_funcWrite)
