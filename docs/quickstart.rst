介绍
====

angr 是一个支持多种指令架构的二进制分析工具包，能够执行动态符号执行（包含 Mayhem、KLEE 等功能）以及对二进制文件进行各种静态分析。如果你想学习如何使用它，你来对地方了！

我们尽量让使用 angr 变得尽可能简单——我们的目标是创建一个用户友好的二进制分析套件，允许用户简单地启动 iPython 并通过几个命令轻松执行密集的二进制分析。话虽如此，二进制分析是复杂的，这让 angr 也很复杂。本文档试图解决这个问题，提供对 angr 及其设计的详解和探索方式。

要编程分析一个二进制文件，必须克服几个挑战。它们大致是：

* 将二进制文件加载到分析程序中。
* 将二进制文件转换为中间代码（IR）。
* 执行实际分析。这可能是：

  * 部分或全程序静态分析（例如，依赖分析，程序切片）。
  * 程序状态空间的符号探索（例如，“我们能执行它直到找到溢出吗？”）。
  * 上述的分析过程的组合（例如，“让我们只执行与内存写入相关的程序切片，以找到溢出。”）

angr 有应对以上所述的所有挑战的组件。本文件将解释每个组件的工作原理，以及如何通过它们来实现你的目标。

获取支持
--------

要获得 angr 的帮助，你可以：

* 在 `angr Discord 服务器 <http://discord.angr.io>`_ 上与我们聊天
* 在相应的 GitHub 仓库中打开一个 Issue

引用 angr
--------

如果你在学术作品中使用了 angr，请引用为其发布的论文：

.. code-block:: bibtex

   @article{shoshitaishvili2016state,
     title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
     author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, Jessie and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={IEEE Symposium on Security and Privacy},
     year={2016}
   }

   @article{stephens2016driller,
     title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
     author={Stephens, Nick and Grosen, Jessie and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={NDSS},
     year={2016}
   }

   @article{shoshitaishvili2015firmalice,
     title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
     author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
     booktitle={NDSS},
     year={2015}
   }

深入了解
--------

你可以阅读这篇 `论文
<https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf>`_，
解释了一些内部原理、算法和使用的技术，以更好地理解底层发生的事情。

如果你喜欢打 CTF 并希望以类似的方式学习 angr，`angr_ctf <https://github.com/jakespringer/angr_ctf>`_ 将是一个有趣的方式，让你熟悉 angr 的许多符号执行功能。 `angr_ctf 这个仓库 <https://github.com/jakespringer/angr_ctf>`_ 由 `@jakespringer <https://github.com/jakespringer>`_ 维护。