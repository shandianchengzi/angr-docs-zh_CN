常见问题
==========================

This is a collection of commonly-asked "how do I do X?" questions and other
general questions about angr, for those too lazy to read this whole document.

If your question is of the form "how do I fix X issue after installing", see
also the Troubleshooting section of the :ref:`install instructions <安装
angr>`_ .

为什么叫 angr？
---------------------

angr 分析的核心是 VEX IR，当某件事是 vexing 的，它会使你 angry。

“angr” 应该如何书写？
------------------------------

全小写，即使在句子的开头也是如此。这是一个反专有名词。

为什么符号执行没有按我想要的方式运行？
----------------------------------------------------

符号执行的通用调试技术如下：


* Check your simulation manager for errored states. ``print(simgr)`` is a good
  place to start, and if you see anything to do with "errored", go for
  ``print(simgr.errored)``.
* If you have any errored states and it's not immediately obvious what you did
  wrong, you can get a `pdb <https://docs.python.org/3/library/pdb.html>`_ shell
  at the crash site by going ``simgr.errored[n].debug()``.
* If no state has reached an address you care about, you should check the path
  each state has gone down: ``import pprint;
  pprint.pprint(state.history.descriptions.hardcopy)``. This will show you a
  high-level summary of what the symbolic execution engine did at each step
  along the state's history. You will be able to see from this a basic block
  trace and also a list of executed simprocedures. If you're using unicorn
  engine, you can check ``state.history.bbl_addrs.hardcopy`` to see what blocks
  were executed in each invocation of unicorn.
* If a state is going down the wrong path, you can check what constraints caused
  it to go that way: ``print(state.solver.constraints)``. If a state has just
  gone past a branch, you can check the most recent branch condition with
  ``state.history.events[-1]``.

如何获取有关 angr 正在做什么的诊断信息？
--------------------------------------------------------------

angr 使用标准的 ``logging`` 模块进行日志记录，每个包和子模块都会创建一个新的记录器。

获取调试输出的最简单方法如下：

.. code-block:: python

   import logging
   logging.getLogger('angr').setLevel('DEBUG')

你可能想使用 ``INFO`` 或其他级别。默认情况下，angr 会在 ``WARNING`` 级别启用日志记录。

每个 angr 模块都有它自己的 logger，只要使用模块路径就可以找到它，即层次结构中所有 Python 模块加上自身，用点连接。例如， ``angr.analyses.cfg`` 。根据 Python 日志记录模块的工作方式，你可以通过为父模块设置一个详细级别来设置所有子模块的详细级别。例如， ``logging.getLogger('angr.analyses').setLevel('INFO')`` 将使 CFG 以及所有其他分析器在 INFO 级别记录日志。

为什么 angr 这么慢？
--------------------

这很复杂！ :ref:`如何提高速度`

如何使用 angr 找到漏洞？
------------------------

这很复杂！最简单的方法是定义一个“漏洞条件”，例如，“指令指针变成了一个符号变量”，然后运行符号探索，直到找到符合该条件的状态，然后将输入转储为测试用例。然而，你很快就会遇到路径爆炸问题。如何解决这个问题取决于你。你的解决方案可能像添加一个 ``avoid`` 条件一样简单，也可能像实现 CMU 的 MAYHEM 系统作为探索技术一样复杂。

为什么选择 VEX 而不是其他 IR（如 LLVM、REIL、BAP 等）？
------------------------------------------------------------

我们在 angr 中有两个设计目标影响了这个选择：


#. angr needed to be able to analyze binaries from multiple architectures. This
   mandated the use of an IR to preserve our sanity, and required the IR to
   support many architectures.
#. We wanted to implement a binary analysis engine, not a binary lifter. Many
   projects start and end with the implementation of a lifter, which is a time
   consuming process. We needed to take something that existed and already
   supported the lifting of multiple architectures.

Searching around the internet, the major choices were:


* LLVM is an obvious first candidate, but lifting binary code to LLVM cleanly is
  a pain. The two solutions are either lifting to LLVM through QEMU, which is
  hackish (and the only implementation of it seems very tightly integrated into
  S2E), or McSema, which only supported x86 at the time but has since gone
  through a rewrite and gotten support for x86-64 and aarch64.
* TCG is QEMU's IR, but extracting it seems very daunting as well and
  documentation is very scarce.
* REIL seems promising, but there is no standard reference implementation that
  supports all the architectures that we wanted. It seems like a nice academic
  work, but to use it, we would have to implement our own lifters, which we
  wanted to avoid.
* BAP was another possibility. When we started work on angr, BAP only supported
  lifting x86 code, and up-to-date versions of BAP were only available to
  academic collaborators of the BAP authors. These were two deal-breakers. BAP
  has since become open, but it still only supports x86_64, x86, and ARM.
* VEX was the only choice that offered an open library and support for many
  architectures. As a bonus, it is very well documented and designed
  specifically for program analysis, making it very easy to use in angr.

While angr uses VEX now, there's no fundamental reason that multiple IRs cannot
be used. There are two parts of angr, outside of the ``angr.engines.vex``
package, that are VEX-specific:


* the jump labels (i.e., the ``Ijk_Ret`` for returns, ``Ijk_Call`` for calls,
  and so forth) are VEX enums.
* VEX treats registers as a memory space, and so does angr. While we provide
  accesses to ``state.regs.rax`` and friends, on the backend, this does
  ``state.registers.load(8, 8)``, where the first ``8`` is a VEX-defined offset
  for ``rax`` to the register file.

To support multiple IRs, we'll either want to abstract these things or translate
their labels to VEX analogues.

为什么一些 ARM 地址会偏移一个字节？
--------------------------------------

为了编码 ARM 代码地址的 THUMB 模式，我们将最低位设置为 1。这个约定来自 LibVEX，不完全由我们决定！如果你看到一个奇数的 ARM 地址，那就意味着 ``address - 1`` 处的代码处于 THUMB 模式。

如何序列化 angr 对象？
--------------------------------

`Pickle <https://docs.python.org/2/library/pickle.html>`_ 可以使用。然而，Python 默认使用一个非常旧的 pickle 协议，它不支持更复杂的 Python 数据结构，所以你必须指定一个 `更高级的数据流格式 <https://docs.python.org/2/library/pickle.html#data-stream-format>`_ 。最简单的方法是使用 ``pickle.dumps(obj, -1)``。

``UnsupportedIROpError("floating point support disabled")`` 是什么意思？
-------------------------------------------------------------------------------

如果你正在使用 CGC 分析（例如 driller 或 rex），可能会出现这种情况。
在 CGC 分析中，angr 的浮点支持已被禁用，原因如下：


* Libvex's representation of floating point numbers is imprecise - it converts
  the 80-bit extended precision format used by the x87 for computation to 64-bit
  doubles, making it impossible to get precise results
* There is very limited implementation support in angr for the actual primitive
  operations themselves as reported by libvex, so you will often get a less
  friendly "unsupported operation" error if you go too much further
* For what operations are implemented, the basic optimizations that allow
  tractability during symbolic computation (AST deduplication, operation
  collapsing) are not implemented for floating point ops, leading to gigantic
  ASTs
* There are memory corruption bugs in z3 that get triggered frighteningly easily
  when you're using huge workloads of mixed floating point and bitvector ops. We
  haven't been able to get a testcase that doesn't involve "just run angr" for
  the z3 guys to investigate.

Instead of trying to cope with all of these, we have simply disabled floating
point support in the symbolic execution engine. To allow for execution in the
presence of floating point ops, we have enabled an exploration technique called
the
`https://github.com/angr/angr/blob/master/angr/exploration_techniques/oppologist.py
<oppologist>` that is supposed to catch these issues, concretize their inputs,
and run the problematic instructions through qemu via unicorn engine, allowing
execution to continue. The intuition is that the specific values of floating
point operations don't typically affect the exploitation process.

If you're seeing this error and it's terminating the analysis, it's probably
because you don't have unicorn installed or configured correctly. If you're
seeing this issue just in a log somewhere, it's just the oppologist kicking in
and you have nothing to worry about.

为什么 angr 的 CFG 与 IDA 的不同？
---------------------------------------

主要有两个原因：

* IDA 不会在函数调用处拆分基本块。angr 会，因为它们是一种控制流，基本块在控制流指令处结束。通常 IDA 形成的那种超长的控制流对执行自动分析是没有必要的。
* 如果另一个块跳到它的中间，IDA 会拆分基本块。这称为基本块规范化，angr 默认不执行此操作，因为对于大多数静态分析来说这是不必要的。你可以通过在 CFG 分析中传递 ``normalize=True`` 来启用它。

为什么在 SimInspect 断点期间从状态读取时会得到不正确的寄存器值？
------------------------------------------------------------------------------------------------

当启用优化时，libVEX 会消除单个基本块内的重复寄存器写入。关闭 IR 优化可以使所有内容在任何时候都看起来正确。

在指令指针的情况下，即使禁用了优化，libVEX 也会经常省略块中间的写入。在这种情况下，你应该使用 ``state.scratch.ins_addr`` 来获取当前的指令指针。
