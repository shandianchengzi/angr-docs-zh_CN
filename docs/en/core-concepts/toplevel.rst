核心概念
=============

要开始使用 angr，您需要对一些基本的 angr 概念有一个基本的概述，并了解如何构建一些基本的 angr 对象。我们将通过检查在加载二进制文件后直接可用的内容来介绍这些概念！

您在 angr 中的第一个操作将始终是将二进制文件加载到一个 *project* 中。我们将使用 ``/bin/true`` 作为这些示例。

.. code-block:: python

   >>> import angr
   >>> proj = angr.Project('/bin/true')

项目是 angr 中的控制基础。通过它，您将能够在刚刚加载的可执行文件上调度分析和模拟。在 angr 中，您几乎每个对象都依赖于某种形式的项目的存在。

.. tip::
   在 IPython（或其他 Python 命令行解释器）中使用和探索 angr 是我们设计 angr 的主要用例。当您不确定有哪些接口可用时，制表符补全是您的朋友！

   有时，IPython 中的制表符补全可能很慢。我们发现以下解决方法对于不降低补全结果的有效性非常有帮助：

   .. code-block:: python

      # 将此文件放在 IPython 配置文件的启动目录中，以避免每次运行它。
      import IPython
      py = IPython.get_ipython()
      py.Completer.use_jedi = False


基本属性
----------------

首先，我们有关于项目的一些基本属性：它的 CPU 架构、文件名和入口点的地址。

.. code-block:: python

   >>> import monkeyhex # 这将以十六进制格式化数字结果
   >>> proj.arch
   <Arch AMD64 (LE)>
   >>> proj.entry
   0x401670
   >>> proj.filename
   '/bin/true'


* *arch* 是一个 ``archinfo.Arch`` 对象的实例，用于表示程序编译的体系结构，本例中为小端的 amd64。它包含有关运行在其上的 CPU 的大量文书数据，您可以在 `这里随意查看
  <https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py>`_。您关心的常见属性是 ``arch.bits``、 ``arch.bytes`` （这是一个 ``@property`` 声明在 `主要的 Arch 类
  <https://github.com/angr/archinfo/blob/master/archinfo/arch.py>`_ 上）、 ``arch.name`` 和 ``arch.memory_endness``。
* *entry* 是二进制文件的入口点！
* *filename* 是二进制文件的绝对文件名。引人入胜的东西！

加载
----------

从二进制文件到其在虚拟地址空间中的表示形式是相当复杂的！我们有一个名为 CLE 的模块来处理这个过程。CLE 的结果称为加载器，可以在 ``.loader`` 属性中访问。我们将在 :ref:`不久的将来 <加载二进制文件>` 中详细介绍如何使用它，但现在只需知道您可以使用它来查看 angr 加载到您的程序旁边的共享库，并执行有关加载的地址空间的基本查询。

.. code-block:: python

   >>> proj.loader
   <Loaded true, maps [0x400000:0x5004000]>

   >>> proj.loader.shared_objects # 对您来说可能看起来有点不同！
   {'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
    'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

   >>> proj.loader.min_addr
   0x400000
   >>> proj.loader.max_addr
   0x5004000

   >>> proj.loader.main_object  # 我们已经将几个二进制文件加载到这个项目中。这是主要的！
   <ELF Object true, maps [0x400000:0x60721f]>

   >>> proj.loader.main_object.execstack  # 示例查询：此二进制文件是否具有可执行堆栈？
   False
   >>> proj.loader.main_object.pic  # 示例查询：此二进制文件是否是位置无关的？
   True

工厂（factory）
-----------

angr中有很多类，其中大多数需要一个项目实例化。为了避免让你到处传递项目，我们提供了 ``project.factory``，它有几个方便的构造函数，用于你经常需要使用的常见对象。

本节还将作为几个基本angr概念的介绍。系好安全带！

基本块
~~~~~~

首先，我们有 ``project.factory.block()``，它用于从给定地址提取一个 `基本块 <https://en.wikipedia.org/wiki/Basic_block>`_ 的代码。这是一个重要的事实—— *angr以基本块为单位分析代码。* 你将得到一个 Block 对象，它可以告诉你关于这段代码块的很多有趣的事情：

.. code-block:: python

   >>> block = proj.factory.block(proj.entry)  # 从程序的入口点提取一个代码块
   <Block for 0x401670, 42 bytes>

   >>> block.pp()                             # 美观地打印反汇编到标准输出
   0x401670:       xor     ebp, ebp
   0x401672:       mov     r9, rdx
   0x401675:       pop     rsi
   0x401676:       mov     rdx, rsp
   0x401679:       and     rsp, 0xfffffffffffffff0
   0x40167d:       push    rax
   0x40167e:       push    rsp
   0x40167f:       lea     r8, [rip + 0x2e2a]
   0x401686:       lea     rcx, [rip + 0x2db3]
   0x40168d:       lea     rdi, [rip - 0xd4]
   0x401694:       call    qword ptr [rip + 0x205866]

   >>> block.instructions                     # 有多少条指令？
   0xb
   >>> block.instruction_addrs                # 指令的地址是什么？
   [0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]

此外，你可以使用 Block 对象获取代码块的其他表示形式：

.. code-block:: python

   >>> block.capstone                          # capstone反汇编
   <CapstoneBlock for 0x401670>
   >>> block.vex                               # VEX IRSB（这是一个Python内部地址，不是程序地址）
   <pyvex.block.IRSB at 0x7706330>

状态
~~~~~~

这里有另一个关于 angr 的事实 - ``Project`` 对象仅代表程序的“初始化镜像”。当你使用 angr 执行时，你正在处理一个表示*模拟程序状态*的特定对象 - ``SimState``。让我们现在抓取一个！

.. code-block:: python

   >>> state = proj.factory.entry_state()
   <SimState @ 0x401670>

一个 SimState 包含程序的内存、寄存器、文件系统数据……任何可以被执行改变的“实时数据”都在状态中有一个位置。我们稍后会详细介绍如何与状态交互，但现在，让我们使用 ``state.regs`` 和 ``state.mem`` 来访问该状态的寄存器和内存：

.. code-block:: python

   >>> state.regs.rip        # 获取当前指令指针
   <BV64 0x401670>
   >>> state.regs.rax
   <BV64 0x1c>
   >>> state.mem[proj.entry].int.resolved  # 将入口点的内存解释为一个 C int
   <BV32 0x8949ed31>

这些不是 Python 的整数！这些是 *位向量* 。Python 整数没有与 CPU 上的字相同的语义，例如溢出时环绕，所以我们使用位向量，你可以将其视为由一系列位表示的整数，以在 angr 中表示 CPU 数据。注意，每个位向量都有一个 ``.length`` 属性，描述它的宽度（以位为单位）。

我们很快就会学习如何使用它们，但现在，这里是如何从 Python 整数转换为位向量并返回的方法：

.. code-block:: python

   >>> bv = state.solver.BVV(0x1234, 32)       # 创建一个值为 0x1234 的 32 位宽位向量
   <BV32 0x1234>                               # BVV 代表位向量值
   >>> state.solver.eval(bv)                # 转换为 Python 整数
   0x1234

你可以将这些位向量存储回寄存器和内存，或者你可以直接存储一个 Python 整数，它将被转换为适当大小的位向量：

.. code-block:: python

   >>> state.regs.rsi = state.solver.BVV(3, 64)
   >>> state.regs.rsi
   <BV64 0x3>

   >>> state.mem[0x1000].long = 4
   >>> state.mem[0x1000].long.resolved
   <BV64 0x4>

``mem`` 接口一开始有点令人困惑，因为它使用了一些相当复杂的 Python 魔法。简短的使用方法是：

* 使用 array[index] 表示法指定地址
* 使用 ``.<type>`` 指定内存应被解释为 :class:`type`（常见值：char, short, int, long, size_t, uint8_t, uint16_t...）
* 从那里，你可以：

  * 存储一个值，可以是位向量或 Python 整数
  * 使用 ``.resolved`` 将值作为位向量获取
  * 使用 ``.concrete`` 将值作为 Python 整数获取

稍后将介绍更多高级用法！

最后，如果你尝试读取更多寄存器，你可能会遇到一个非常奇怪的值：

.. code-block:: python

   >>> state.regs.rdi
   <BV64 reg_48_11_64{UNINITIALIZED}>

这仍然是一个 64 位位向量，但它不包含数值。相反，它有一个名称！这被称为*符号变量*，它是符号执行的基础。不要惊慌！我们将在两章后详细讨论这一切。

模拟管理器
~~~~~~~~~~~

如果状态让我们表示程序在某个时间点的状态，那么必须有一种方法将其推进到*下一个*时间点。模拟管理器是 angr 中用于执行、模拟、你想怎么称呼都行的主要接口。作为简短介绍，让我们展示如何将我们之前创建的状态向前推进几个基本块。

首先，我们创建将要使用的模拟管理器。构造函数可以接受一个状态或一组状态。

.. code-block:: python

   >>> simgr = proj.factory.simulation_manager(state)
   <SimulationManager with 1 active>
   >>> simgr.active
   [<SimState @ 0x401670>]

一个模拟管理器可以包含多个 *存储区* 的状态。默认存储区 ``active`` 用我们传入的状态初始化。如果我们还没有看够，可以查看 ``simgr.active[0]`` 来进一步查看我们的状态。

现在……准备好，我们要进行一些执行。

.. code-block:: python

   >>> simgr.step()

我们刚刚执行了一个基本块的符号执行！我们可以再次查看活动存储区，注意到它已经更新，而且，它 **没有** 修改我们的原始状态。SimState 对象在执行中被视为不可变的 - 你可以安全地使用单个状态作为多个执行轮次的“基础”。

.. code-block:: python

   >>> simgr.active
   [<SimState @ 0x1020300>]
   >>> simgr.active[0].regs.rip                 # 新的和令人兴奋的！
   <BV64 0x1020300>
   >>> state.regs.rip                           # 仍然是一样的！
   <BV64 0x401670>

``/bin/true`` 不是一个很好的例子来描述如何使用符号执行做有趣的事情，所以我们现在就到此为止。

分析
--------

angr 预装了几个内置分析，你可以用它们从程序中提取一些有趣的信息。它们如下：

.. code-block::

   >>> proj.analyses.            # 在 ipython 中按 TAB 键以获取自动完成列表：
    proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses
    proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker
    proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery
    proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast
    proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting
    proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG
    proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG
    proj.analyses.CFGFast              proj.analyses.Reassembler

本书稍后会记录其中一些，但一般来说，如果你想找到如何使用某个分析，你应该查看 :py:mod:`angr.analyses` 的 API 文档。作为一个非常简短的例子：这里是如何构建和使用一个快速控制流图：

.. code-block:: python

   # 最初，当我们加载这个二进制文件时，它还将所有依赖项加载到相同的虚拟地址空间
   # 这对于大多数分析来说是不理想的。
   >>> proj = angr.Project('/bin/true', auto_load_libs=False)
   >>> cfg = proj.analyses.CFGFast()
   <CFGFast Analysis Result at 0x2d85130>

   # cfg.graph 是一个充满 CFGNode 实例的 networkx 有向图
   # 你应该去查找 networkx 的 API 以了解如何使用它！
   >>> cfg.graph
   <networkx.classes.digraph.DiGraph at 0x2da43a0>
   >>> len(cfg.graph.nodes())
   951

   # 要获取给定地址的 CFGNode，请使用 cfg.get_any_node
   >>> entry_node = cfg.get_any_node(proj.entry)
   >>> len(list(cfg.graph.successors(entry_node)))
   2

接下来做什么？
---------

读完这页，你应该已经熟悉了几个重要的 angr 概念：基本块、状态、位向量、模拟管理器和分析。除了将 angr 用作一个美化的调试器之外，你还不能做任何有趣的事情！继续阅读，你将解锁更深层的能力……
