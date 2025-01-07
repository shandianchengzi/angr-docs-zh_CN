安装 angr
========

angr 是一个适用于 Python 3.10+ 的库，必须安装到 Python 环境中才能使用。

从 PyPI 安装
----------

angr 发布在 `PyPI <https://pypi.org/>`_ 上，从 PyPI 安装是安装 angr 最简单和最推荐的方式。即，使用 pip 安装 angr：

.. code-block:: bash

   pip install angr

.. tip::

   建议安装时使用隔离的 Python 环境，不要全局安装 angr。因为隔离的 Python 环境可以减少依赖冲突，在调试时也有助于重现问题。一些流行的工具包括：

   * `venv <https://docs.python.org/3/library/venv.html>`_
   * `pipenv <https://pipenv.pypa.io/en/latest/>`_
   * `virtualenv <https://virtualenv.pypa.io/en/latest/>`_
   * `virtualenvwrapper <https://virtualenvwrapper.readthedocs.io/en/latest/>`_
   * `conda <https://docs.conda.io/en/latest/>`_

.. note::

   PyPI 分发版包含了大多数流行系统配置的二进制包。如果您使用的系统不受二进制包支持，则需要从源代码构建 C 依赖项（译者注：意思是有一些组件是编译成二进制形式进行分发的，需要对不同的系统做适配，angr 已经对大多数流行的操作系统（如Ubuntu、Windows）做适配了，但也没有覆盖所有的操作系统，如果你发现 PyPI 装的用不了，就必须源码安装）。有关更多信息，请参见 `从源代码安装`_ 部分。

从源代码安装
------------

angr 是多个 Python 包的集合，每个包都发布在 GitHub 上。从源代码安装 angr 最简单的方法是使用 `angr-dev <https://github.com/angr/angr-dev>`_。

要手动设置开发环境，首先确保安装了构建依赖项。这些依赖项包括 Python 开发时用到的头文件、 ``make`` 和 C 编译器。在 Ubuntu 上，可以使用以下命令安装：

.. code-block:: bash

   sudo apt-get install python3-dev build-essential

然后，按顺序检出并安装以下包：

* `archinfo <https://github.com/angr/archinfo>`_
* `pyvex <https://github.com/angr/pyvex>`_ (使用 ``--recursive`` 克隆)
* `cle <https://github.com/angr/cle>`_
* `claripy <https://github.com/angr/claripy>`_
* `ailment <https://github.com/angr/ailment>`_
* `angr <https://github.com/angr/angr>`_ (使用 ``pip install`` 和 ``--no-build-isolation`` )

使用 Docker 安装
--------------

angr 团队在 Docker Hub 上维护了一个包含 angr 及其依赖项的容器镜像。可以使用以下命令拉取该镜像：

.. code-block:: bash

   docker pull angr/angr

可以使用以下命令运行该镜像：

.. code-block:: bash

   docker run -it angr/angr

这将启动容器中的一个 shell。在这个 shell 中，angr 已安装并可以使用。

故障排除
--------

angr has no attribute Project，或类似问题
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

如果可以导入 angr 但缺少 ``Project`` 类，可能是以下两个问题之一：

#. 工作目录中有一个名为 ``angr.py`` 的脚本。将其重命名为其他名称。
#. 工作目录中有一个名为 ``angr`` 的文件夹，可能是克隆的仓库。将工作目录更改为其他位置。

AttributeError: 'module' object has no attribute 'KS_ARCH_X86'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

这个问题可能是因为安装了 ``keystone`` 包，而这与 angr 的可选依赖项 ``keystone-engine`` 包冲突。卸载 ``keystone`` 并安装 ``keystone-engine`` 即可。