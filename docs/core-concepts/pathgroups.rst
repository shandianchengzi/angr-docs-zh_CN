模拟管理器（Simulation Managers）
===================

angr 中最重要的控制接口是 SimulationManager，它允许你同时控制多个状态的符号执行，应用搜索策略来探索程序的状态空间。在这里，你将学习如何使用它。

模拟管理器让你以一种巧妙的方式管理多个状态。状态被组织成“存储区”，你可以根据需要前进、过滤、合并和移动这些存储区。这使你能够以不同的速率前进两个不同的状态存储区，然后将它们合并在一起。大多数操作的默认存储区是 ``active`` 存储区，这是你初始化新的模拟管理器时状态被放置的地方。

Stepping
^^^^^^^^

模拟管理器最基本的功能是将给定存储区（stash）中的所有状态向前推进一个基本块。你可以使用 ``.step()`` 来实现这一点。

.. code-block:: python

   >>> import angr
   >>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
   >>> state = proj.factory.entry_state()
   >>> simgr = proj.factory.simgr(state)
   >>> simgr.active
   [<SimState @ 0x400580>]

   >>> simgr.step()
   >>> simgr.active
   [<SimState @ 0x400540>]

当然，存储区模型的真正强大之处在于，当一个状态遇到符号分支条件时，两个后继状态都会出现在存储区中，你可以同步推进它们。当你不太关心精确控制分析，只是想一步步执行直到没有可执行的步骤时，你可以使用 ``.run()`` 方法。

.. code-block:: python

   # Step until the first symbolic branch
   >>> while len(simgr.active) == 1:
   ...    simgr.step()

   >>> simgr
   <SimulationManager with 2 active>
   >>> simgr.active
   [<SimState @ 0x400692>, <SimState @ 0x400699>]

   # Step until everything terminates
   >>> simgr.run()
   >>> simgr
   <SimulationManager with 3 deadended>

我们现在有 3 个 deadended 状态！当一个状态在执行过程中未能产生任何后继状态时，例如，因为它到达了一个 ``exit`` 系统调用，它将从 active 存储区中移除并放置在 ``deadended`` 存储区中。

存储区（Stash）管理
^^^^^^^^^^

让我们看看如何处理其他存储区。

要在存储区之间移动状态，请使用 ``.move()``，它接受 ``from_stash``、 ``to_stash`` 和 ``filter_func``（可选，默认是移动所有内容）。例如，让我们移动输出中包含某个字符串的所有状态：

.. code-block:: python

   >>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
   >>> simgr
   <SimulationManager with 2 authenticated, 1 deadended>

我们能够通过请求将状态移动到新创建的名为 "authenticated" 的存储区中。该存储区中的所有状态在其 stdout 中都有 "Welcome"，这目前是一个不错的指标。

每个存储区只是一个列表，你可以索引或迭代该列表以访问每个单独的状态，但也有一些替代方法来访问这些状态。如果在存储区名称前加上 ``one_``，你将获得存储区中的第一个状态。如果在存储区名称前加上 ``mp_``，你将获得该存储区的 `mulpyplexed <https://github.com/zardus/mulpyplexer>`_ 版本。

.. code-block:: python

   >>> for s in simgr.deadended + simgr.authenticated:
   ...     print(hex(s.addr))
   0x1000030
   0x1000078
   0x1000078

   >>> simgr.one_deadended
   <SimState @ 0x1000030>
   >>> simgr.mp_authenticated
   MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
   >>> simgr.mp_authenticated.posix.dumps(0)
   MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
       '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])

当然， ``step`` 、 ``run`` 和任何其他操作单个存储区路径的方法都可以接受一个 ``stash`` 参数，指定要操作的存储区。

模拟管理器为你提供了许多有趣的工具来管理你的存储区。我们现在不会介绍它们的全部内容，但你应该查看 :ref:`API 参考手册 <API 参考手`_ 。

存储区类型
-----------

你可以根据需要使用存储区，但有一些存储区将用于分类某些特殊类型的状态。这些存储区包括：

.. list-table::
   :header-rows: 1

   * - 存储区
     - 描述
   * - active
     - 这个存储区包含默认情况下将被执行的状态，除非指定了其他存储区。
   * - deadended
     - 当状态由于某种原因无法继续执行时，包括没有更多有效指令、所有后继状态都不可满足或无效的指令指针时，状态将进入 deadended 存储区。
   * - pruned
     - 使用 ``LAZY_SOLVES`` 时，状态不会被检查是否可满足，除非绝对必要。当发现状态在 ``LAZY_SOLVES`` 存在的情况下不可满足时，将遍历状态层次结构以确定其历史中最初变得不可满足的时间点。从该点开始的所有后代状态（由于状态不能变得可满足）将被修剪并放入此存储区。
   * - unconstrained
     - 如果在 SimulationManager 构造函数中提供了 ``save_unconstrained`` 选项，则被确定为不受约束的状态（即，指令指针由用户数据或其他符号数据源控制）将被放置在这里。
   * - unsat
     - 如果在 SimulationManager 构造函数中提供了 ``save_unsat`` 选项，则被确定为不可满足的状态（即，它们具有矛盾的约束，例如输入必须同时是 "AAAA" 和 "BBBB"）将被放置在这里。


还有一个状态列表不是存储区： ``errored`` 。如果在执行过程中引发错误，则状态将被包装在一个 ``ErrorRecord`` 对象中，该对象包含状态和引发的错误，然后记录将被插入到 ``errored`` 中。你可以通过 ``record.state`` 获取引发错误时执行开始时的状态，可以通过 ``record.error`` 查看引发的错误，并且可以通过 ``record.debug()`` 在错误发生的位置启动调试 shell。这是一个非常宝贵的调试工具！

简单探索（Exploration）
^^^^^^^^^^

符号执行中一个非常常见的操作是找到到达某个地址的状态，同时丢弃所有经过另一个地址的状态。模拟管理器为这种模式提供了一个快捷方式，即 ``.explore()`` 方法。

当使用 ``find`` 参数启动 ``.explore()`` 时，执行将运行直到找到符合查找条件的状态，该条件可以是要停止的指令地址、要停止的地址列表，或者是一个接受状态并返回是否符合某些条件的函数。当 active 存储区中的任何状态符合 ``find`` 条件时，它们将被放置在 ``found`` 存储区中，执行终止。然后你可以探索找到的状态，或者决定丢弃它并继续处理其他状态。你还可以指定一个与 ``find`` 格式相同的 ``avoid`` 条件。当状态符合 avoid 条件时，它将被放入 ``avoided`` 存储区，执行继续。最后，``num_find`` 参数控制在返回之前应找到的状态数量，默认值为 1。当然，如果在找到这么多解决方案之前用完了 active 存储区中的状态，执行将停止。

让我们看一个简单的 crackme 示例 `example <./examples.md#reverseme-modern-binary-exploitation---csci-4968>` ：

首先，我们加载二进制文件。

.. code-block:: python

   >>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')

接下来，我们创建一个 SimulationManager。

.. code-block:: python

   >>> simgr = proj.factory.simgr()

现在，我们符号执行直到找到符合我们条件的状态（即，“win”条件）。

.. code-block:: python

   >>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
   <SimulationManager with 1 active, 1 found>

现在，我们可以从该状态中获取标志！

.. code-block:: python

   >>> s = simgr.found[0]
   >>> print(s.posix.dumps(1))
   Enter password: Congrats!

   >>> flag = s.posix.dumps(0)
   >>> print(flag)
   g00dJ0B!

很简单，不是吗？

其他示例可以通过浏览 :ref:`examples <angr 示例>` 找到。

探索机制
--------

angr 附带了几种预定义的功能，称为 *探索机制* ，可以让你自定义模拟管理器的行为。
其中典型的例子是修改程序状态空间的探索模式——默认的“同时执行所有步骤”策略（即广度优先搜索），使用探索机制，你可以实现例如深度优先搜索。不过，这些技术的能力远不止于此——你可以完全改变 angr 的 step 过程。
如何编写你自己的探索机制将在后面的章节中介绍。

要使用探索机制，请调用 ``simgr.use_technique(tech)``，其中 tech 是 ExplorationTechnique 子类的一个实例。
angr 的内置探索机制可以在 ``angr.exploration_techniques`` 下找到。

以下是一些内置机制的快速概述：

* *DFS* : 深度优先搜索，如前所述。一次只保持一个状态处于活动状态，将其余状态放入 ``deferred`` 存储区，直到它们死锁或出错。
* *Explorer* : 该机制实现了 ``.explore()`` 功能，允许你搜索和避开地址。
* *LengthLimiter* : 限制状态路径的最大长度。
* *LoopSeer* : 使用合理的循环计数近似值丢弃似乎经过太多次循环的状态，将它们放入 ``spinning`` 存储区，如果没有其他可行状态，则重新提取它们。
* *ManualMergepoint* : 将程序中的一个地址标记为合并点，到达该地址的状态将被短暂保留，并在超时内到达相同点的其他状态将被合并。
* *MemoryWatcher* : 监视 simgr 步骤之间系统上可用的内存量，如果内存过低则停止探索。
* *Oppologist* : “操作辩护者”是一个特别有趣的小工具——如果启用此技术并且 angr 遇到不支持的指令，例如奇怪的外来浮点 SIMD 操作，它将具体化该指令的所有输入，并使用 unicorn 引擎模拟单个指令，从而允许执行继续。
* *Spiller* : 当有太多状态处于活动状态时，该技术可以将其中一些状态转储到磁盘以保持内存消耗较低。
* *Threading* : 为步进过程添加线程级并行性。这并没有太大帮助，因为 Python 的全局解释器锁，但如果你的程序分析在 angr 的本地代码依赖项（unicorn、z3、libvex）中花费了大量时间，你可以看到一些收益。
* *Tracer* : 一种探索机制，使执行遵循从其他来源记录的动态跟踪。`动态跟踪器库 <https://github.com/angr/tracer>`_ 有一些生成这些跟踪的工具。
* *Veritesting* : 实现了 `CMU 论文 <https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf>`_ 中关于自动识别有用合并点的内容。这非常有用，你可以在 SimulationManager 构造函数中通过 ``veritesting=True`` 自动启用它！请注意，由于它实现静态符号执行的侵入方式，它经常与其他技术不兼容。

查看 :py:class:`~angr.sim_manager.SimulationManager` 和 :py:class:`~angr.exploration_techniques.ExplorationTechnique` 类的 API 文档以获取更多信息。

