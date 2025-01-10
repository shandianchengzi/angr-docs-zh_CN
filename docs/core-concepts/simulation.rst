模拟（Simulation）与相关工具（Instrumentation）
====================================

当你要求在 angr 中 step 执行时，必须有某些东西实际执行这个步骤。angr 使用一系列引擎（具体种类可在 ``SimEngine`` 类的子类中查看）来模拟给定代码段对输入状态的影响。angr 的执行核心只是按顺序尝试所有可用的引擎，选择第一个能够处理该步骤的引擎。以下是默认的引擎列表，按顺序排列：

* 当上一步导致我们进入某个无法继续的状态时，失败引擎会启动
* 当上一步以系统调用结束时，系统调用引擎会启动
* 当当前地址被挂钩时，挂钩引擎会启动
* 当启用了 ``UNICORN`` 状态选项且状态中没有符号数据时，Unicorn 引擎会启动
* VEX 引擎作为最终的后备引擎启动。

SimSuccessors
-------------

实际依次尝试所有引擎的代码是 ``project.factory.successors(state, **kwargs)``，它将其参数传递给每个引擎。这个函数是 ``state.step()`` 和 ``simulation_manager.step()`` 的核心。它返回一个 SimSuccessors 对象，我们之前简要讨论过。SimSuccessors 的目的是对后继状态进行简单分类，存储在各种列表属性中。它们是：

.. list-table::
  :header-rows: 1

  * - 属性
    - 守护条件
    - 指令指针
    - 描述
  * - ``successors``
    - True（可以是符号的，但受限于 True）
    - 可以是符号的（但最多有 256 个解；参见 ``unconstrained_successors``）。
    - 引擎处理的状态的正常、可满足的后继状态。该状态的指令指针可能是符号的（即基于用户输入的计算跳转），因此该状态实际上可能代表 *多个* 潜在的执行继续。
  * - ``unsat_successors``
    - False（可以是符号的，但受限于 False）。
    - 可以是符号的。
    - 不可满足的后继状态。这些是守护条件只能为假的后继状态（即不能跳转的跳转，或必须跳转的跳转的默认分支）。
  * - ``flat_successors``
    - True（可以是符号的，但受限于 True）。
    - 具体值。
    - 如上所述，``successors`` 列表中的状态可以具有符号指令指针。这相当混乱，因为在代码的其他地方（即在 ``SimEngineVEX.process`` 中，当需要将该状态向前推进时），我们假设单个程序状态仅代表代码中的单个位置的执行。为了解决这个问题，当我们在 ``successors`` 中遇到具有符号指令指针的状态时，我们为它们计算所有可能的具体解（最多 256 个），并为每个解制作状态的副本。我们称这个过程为“扁平化”。这些 ``flat_successors`` 是每个具有不同具体指令指针的状态。例如，如果 ``successors`` 中的状态的指令指针是 ``X+5``，其中 ``X`` 的约束是 ``X > 0x800000`` 和 ``X <= 0x800010``，我们会将其扁平化为 16 个不同的 ``flat_successors`` 状态，一个指令指针为 ``0x800006``，一个为 ``0x800007``，依此类推，直到 ``0x800015``。
  * - ``unconstrained_successors``
    - True（可以是符号的，但受限于 True）。
    - 符号的（超过 256 个解）。
    - 在上述扁平化过程中，如果发现指令指针有超过 256 个可能的解，我们假设指令指针已被不受约束的数据覆盖（即用户数据的堆栈溢出）。*这种假设在一般情况下是不可靠的*。这些状态被放置在 ``unconstrained_successors`` 中，而不是 ``successors`` 中。
  * - ``all_successors``
    - 任何
    - 可以是符号的。
    - 这是 ``successors + unsat_successors + unconstrained_successors``。


Breakpoints
-----------

.. todo:: rewrite this to fix the narrative

Like any decent execution engine, angr supports breakpoints. This is pretty
cool! A point is set as follows:

.. code-block:: python

   >>> import angr
   >>> b = angr.Project('examples/fauxware/fauxware')

   # get our state
   >>> s = b.factory.entry_state()

   # add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
   >>> s.inspect.b('mem_write')

   # on the other hand, we can have a breakpoint trigger right *after* a memory write happens.
   # we can also have a callback function run instead of opening ipdb.
   >>> def debug_func(state):
   ...     print("State %s is about to do a memory write!")

   >>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

   # or, you can have it drop you in an embedded IPython!
   >>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)

除了内存写入之外，还有许多其他地方可以中断。以下是列表。你可以在每个事件的 BP_BEFORE 或 BP_AFTER 处中断。

.. list-table::
   :header-rows: 1

   * - Event type
     - Event meaning
   * - mem_read
     - Memory is being read.
   * - mem_write
     - Memory is being written.
   * - address_concretization
     - A symbolic memory access is being resolved.
   * - reg_read
     - A register is being read.
   * - reg_write
     - A register is being written.
   * - tmp_read
     - A temp is being read.
   * - tmp_write
     - A temp is being written.
   * - expr
     - An expression is being created (i.e., a result of an arithmetic operation
       or a constant in the IR).
   * - statement
     - An IR statement is being translated.
   * - instruction
     - A new (native) instruction is being translated.
   * - irsb
     - A new basic block is being translated.
   * - constraints
     - New constraints are being added to the state.
   * - exit
     - A successor is being generated from execution.
   * - fork
     - A symbolic execution state has forked into multiple states.
   * - symbolic_variable
     - A new symbolic variable is being created.
   * - call
     - A call instruction is hit.
   * - return
     - A ret instruction is hit.
   * - simprocedure
     - A simprocedure (or syscall) is executed.
   * - dirty
     - A dirty IR callback is executed.
   * - syscall
     - A syscall is executed (called in addition to the simprocedure event).
   * - engine_process
     - A SimEngine is about to process some code.


These events expose different attributes:

.. list-table::
   :header-rows: 1

   * - 事件类型
     - 属性名称
     - 属性可用性
     - 属性含义
   * - mem_read
     - mem_read_address
     - BP_BEFORE 或 BP_AFTER
     - 正在读取内存的地址。
   * - mem_read
     - mem_read_expr
     - BP_AFTER
     - 该地址处的表达式。
   * - mem_read
     - mem_read_length
     - BP_BEFORE 或 BP_AFTER
     - 内存读取的长度。
   * - mem_read
     - mem_read_condition
     - BP_BEFORE 或 BP_AFTER
     - 内存读取的条件。
   * - mem_write
     - mem_write_address
     - BP_BEFORE 或 BP_AFTER
     - 正在写入内存的地址。
   * - mem_write
     - mem_write_length
     - BP_BEFORE 或 BP_AFTER
     - 内存写入的长度。
   * - mem_write
     - mem_write_expr
     - BP_BEFORE 或 BP_AFTER
     - 正在写入的表达式。
   * - mem_write
     - mem_write_condition
     - BP_BEFORE 或 BP_AFTER
     - 内存写入的条件。
   * - reg_read
     - reg_read_offset
     - BP_BEFORE 或 BP_AFTER
     - 正在读取的寄存器的偏移量。
   * - reg_read
     - reg_read_length
     - BP_BEFORE 或 BP_AFTER
     - 寄存器读取的长度。
   * - reg_read
     - reg_read_expr
     - BP_AFTER
     - 寄存器中的表达式。
   * - reg_read
     - reg_read_condition
     - BP_BEFORE 或 BP_AFTER
     - 寄存器读取的条件。
   * - reg_write
     - reg_write_offset
     - BP_BEFORE 或 BP_AFTER
     - 正在写入的寄存器的偏移量。
   * - reg_write
     - reg_write_length
     - BP_BEFORE 或 BP_AFTER
     - 寄存器写入的长度。
   * - reg_write
     - reg_write_expr
     - BP_BEFORE 或 BP_AFTER
     - 正在写入的表达式。
   * - reg_write
     - reg_write_condition
     - BP_BEFORE 或 BP_AFTER
     - 寄存器写入的条件。
   * - tmp_read
     - tmp_read_num
     - BP_BEFORE 或 BP_AFTER
     - 正在读取的临时变量的编号。
   * - tmp_read
     - tmp_read_expr
     - BP_AFTER
     - 临时变量的表达式。
   * - tmp_write
     - tmp_write_num
     - BP_BEFORE 或 BP_AFTER
     - 正在写入的临时变量的编号。
   * - tmp_write
     - tmp_write_expr
     - BP_AFTER
     - 写入临时变量的表达式。
   * - expr
     - expr
     - BP_BEFORE 或 BP_AFTER
     - IR 表达式。
   * - expr
     - expr_result
     - BP_AFTER
     - 表达式的值（例如 AST）。
   * - statement
     - statement
     - BP_BEFORE 或 BP_AFTER
     - IR 语句的索引（在 IR 基本块中）。
   * - instruction
     - instruction
     - BP_BEFORE 或 BP_AFTER
     - 本机指令的地址。
   * - irsb
     - address
     - BP_BEFORE 或 BP_AFTER
     - 基本块的地址。
   * - constraints
     - added_constraints
     - BP_BEFORE 或 BP_AFTER
     - 正在添加的约束表达式列表。
   * - call
     - function_address
     - BP_BEFORE 或 BP_AFTER
     - 被调用的函数的名称。
   * - exit
     - exit_target
     - BP_BEFORE 或 BP_AFTER
     - 表示 SimExit 的目标的表达式。
   * - exit
     - exit_guard
     - BP_BEFORE 或 BP_AFTER
     - 表示 SimExit 的保护条件的表达式。
   * - exit
     - exit_jumpkind
     - BP_BEFORE 或 BP_AFTER
     - 表示 SimExit 类型的表达式。
   * - symbolic_variable
     - symbolic_name
     - BP_AFTER
     - 正在创建的符号变量的名称。求解器引擎可能会修改此名称（通过附加唯一的 ID 和长度）。检查最终的符号表达式。
   * - symbolic_variable
     - symbolic_size
     - BP_AFTER
     - 正在创建的符号变量的大小。
   * - symbolic_variable
     - symbolic_expr
     - BP_AFTER
     - 表示新符号变量的表达式。
   * - address_concretization
     - address_concretization_strategy
     - BP_BEFORE 或 BP_AFTER
     - 用于解析地址的 SimConcretizationStrategy。断点处理程序可以修改此策略以更改将应用的策略。如果断点处理程序将其设置为 None，则将跳过此策略。
   * - address_concretization
     - address_concretization_action
     - BP_BEFORE 或 BP_AFTER
     - 用于记录内存操作的 SimAction 对象。
   * - address_concretization
     - address_concretization_memory
     - BP_BEFORE 或 BP_AFTER
     - 执行操作的 SimMemory 对象。
   * - address_concretization
     - address_concretization_expr
     - BP_BEFORE 或 BP_AFTER
     - 表示正在解析的内存索引的 AST。断点处理程序可以修改此值以影响正在解析的地址。
   * - address_concretization
     - address_concretization_add_constraints
     - BP_BEFORE 或 BP_AFTER
     - 是否应该/将要为此读取添加约束。
   * - address_concretization
     - address_concretization_result
     - BP_AFTER
     - 已解析的内存地址列表（整数）。断点处理程序可以覆盖这些以产生不同的解析结果。
   * - syscall
     - syscall_name
     - BP_BEFORE 或 BP_AFTER
     - 系统调用的名称。
   * - simprocedure
     - simprocedure_name
     - BP_BEFORE 或 BP_AFTER
     - simprocedure 的名称。
   * - simprocedure
     - simprocedure_addr
     - BP_BEFORE 或 BP_AFTER
     - simprocedure 的地址。
   * - simprocedure
     - simprocedure_result
     - BP_AFTER
     - simprocedure 的返回值。您还可以在 BP_BEFORE 中 *覆盖* 它，这将导致实际的 simprocedure 被跳过，而使用您的返回值。
     * - simprocedure
     - simprocedure
     - BP_BEFORE 或 BP_AFTER
     - 实际的 SimProcedure 对象。
     * - dirty
     - dirty_name
     - BP_BEFORE 或 BP_AFTER
     - dirty 调用的名称。
     * - dirty
     - dirty_handler
     - BP_BEFORE
     - 将用于处理 dirty 调用的函数。您可以覆盖它。
     * - dirty
     - dirty_args
     - BP_BEFORE 或 BP_AFTER
     - dirty 的地址。
     * - dirty
     - dirty_result
     - BP_AFTER
     - dirty 调用的返回值。您还可以在 BP_BEFORE 中 *覆盖* 它，这将导致实际的 dirty 调用被跳过，而使用您的返回值。
     * - engine_process
     - sim_engine
     - BP_BEFORE 或 BP_AFTER
     - 正在处理的 SimEngine。
     * - engine_process
     - successors
     - BP_BEFORE 或 BP_AFTER
     - 定义引擎结果的 SimSuccessors 对象。


在对应断点 callback 函数内，这些属性可以作为 ``state.inspect`` 的成员被访问。你甚至可以修改这些成员的值，并进一步使用！

.. code-block:: python

   >>> def track_reads(state):
   ...     print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
   ...
   >>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)

此外，这些属性中的每一个都可以作为 ``inspect.b`` 的关键字参数，使断点具有条件性：

.. code-block:: python

   # This will break before a memory write if 0x1000 is a possible value of its target expression
   >>> s.inspect.b('mem_write', mem_write_address=0x1000)

   # This will break before a memory write if 0x1000 is the *only* value of its target expression
   >>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

   # This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
   >>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)

很酷的东西！事实上，我们甚至可以指定一个函数作为条件：

.. code-block:: python

   # this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
   # that the basic block starting at 0x8004 was executed sometime in this path's history
   >>> def cond(state):
   ...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

   >>> s.inspect.b('mem_write', condition=cond)

这是一些很酷的东西！

关于 ``mem_read`` 断点的注意事项
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

在执行程序时或在二进制分析时进行内存读取， ``mem_read`` 断点都会被触发。如果你在使用 ``mem_read`` 断点的同时也使用 ``state.mem`` 从内存地址加载数据，那么请注意，断点会被触发，因为你实际上是在读取内存。

因此，如果你想从内存加载数据而不触发任何已设置的 ``mem_read`` 断点，请使用 ``state.memory.load``，并带上关键字参数 ``disable_actions=True`` 和 ``inspect=False``。

这同样适用于 ``state.find``，你可以使用相同的关键字参数来防止触发 ``mem_read`` 断点。
