报告 Bugs
========

如果你发现了 angr 无法解决的问题，并且看起来像是一个 bug ，请告诉我们！

#. 从 angr/binaries 和 angr/angr 创建一个分支
#. 给我们一个包含相关二进制文件的 angr/binaries 的拉取请求
#. 给我们一个包含触发这些二进制文件的测试用例的 angr/angr 的拉取请求，这些测试用例应放在 ``angr/tests/broken_x.py`` 、 ``angr/tests/broken_y.py`` 等文件中

请尽量遵循我们已有的测试用例格式（代码应在一个 test_blah 函数中），这样我们可以很容易地合并并运行这些脚本。

一个例子是：

.. code-block:: python

   def test_some_broken_feature():
       p = angr.Project("some_binary")
       result = p.analyses.SomethingThatDoesNotWork()
       assert result == "what it should *actually* be if it worked"

   if __name__ == '__main__':
       test_some_broken_feature()

这将 *极大地* 帮助我们重现你的 bug 并更快地修复它。

理想情况下，当 bug 被修复时，你的测试用例通过（即，最后的断言不会引发 AssertionError）。

然后，我们可以修复 bug 并将 ``broken_x.py`` 重命名为 ``test_x.py`` ，测试用例将在每次推送时在我们的内部 CI 中运行，确保我们不会再次破坏这个功能。

开发 angr
========

以下是一些指南，以便我们保持代码库的良好状态！

pre-commit
----------

许多 angr 仓库包含由 `pre-commit <https://pre-commit.com/>`_ 提供的 pre-commit hooks（译者注：Pre-commit hooks 是 Git 提交前自动执行的脚本，用于检查代码质量、格式规范或依赖项，以确保提交内容符合项目要求）。安装它就像 ``pip install pre-commit`` 一样简单。在 ``git`` 克隆一个 angr 仓库后，如果仓库包含 ``.pre-commit-config.yaml`` ，运行 ``pre-commit install``。未来的 ``git`` 提交现在将自动调用这些 hooks。

编码风格
--------

我们使用 `black <https://github.com/psf/black>`_ 格式化我们的代码，并尽量接近 `PEP8 代码规范 <http://legacy.python.org/dev/peps/pep-0008/>`_ ，在合理的范围内不做愚蠢的事情。如果你使用 Vim， `python-mode <https://github.com/klen/python-mode>`_ 插件可以满足你的所有需求。你也可以 `手动配置 <https://wiki.python.org/moin/Vim>`_ vim 以采用这种行为。

最重要的是，请在编写 angr 代码时考虑以下几点：

* 尽量使用属性访问（参见 ``@property`` 装饰器）来替代 getter 和 setter 方法。这不是 Java，属性访问在 iPython 中支持 Tab 自动补全。话虽如此，也要合理使用：属性访问应当是快速的。一个经验法则是，如果某个操作可能需要约束求解，那么它就不应该作为属性。

* 请使用来自 `angr-dev 仓库的 pylintrc 文件 <https://github.com/angr/angr-dev/blob/master/pylintrc>`_ 。该配置相对宽松，但如果 pylint 在这些设置下报错，我们的 CI 服务器将会使你的贡献 build 失败。

* 在【任何情况】下都【不要】 ``raise Exception`` 或 ``assert False``。 **请使用正确的异常类型** 。如果没有合适的异常类型，请继承当前模块的核心异常类（例如， angr 中的 ``AngrError`` ， SimuVEX 中的 ``SimError`` 等）并抛出它。我们会在适当的位置捕获并正确处理指定类型的错误，但 ``AssertionError`` 和 ``Exception`` 在任何地方都不会被处理，它们会强制终止分析过程。

* 避免使用制表符，改用空格缩进。虽然不一定放之四海而皆准，但是通用的标准往往是 4 个空格。从一开始就遵循这个标准是个好主意，因为合并混合使用制表符和空格缩进的代码会非常麻烦。

* 避免超长的代码行。偶尔写较长的代码行是可以的，但请记住，过长的代码行更难阅读，应尽量避免。让我们尝试将代码长度控制在 **120 个字符以内** 。

* 避免编写过长的函数，通常将其拆分为多个小函数会更好。

* 始终使用 ``_`` 而不是 ``__`` 作为私有成员（这样我们在调试时可以访问它们）。 你可能认为没有人有调用某个现有的函数的需要，但相信我们，你错了。

* 使用 ``black`` 格式化你的代码；相关配置已定义在 ``pyproject.toml`` 文件中。

文档
----

请为您的代码编写文档。每个 *类定义* 和 *公共函数定义* 都应该有一些描述：

* 功能描述。
* 参数的类型和含义。
* 返回值的描述。

我们的代码检查工具 linter 会强制要求编写类的文档字符串（docstring）。在任何情况下，你都不应该编写一个除了类名之外没有提供任何额外信息的类。您应该尽量描述该类适用的环境。如果该类不应由最终用户实例化，请描述它是如何生成的以及如何获取其实例。如果该类可以由最终用户实例化，请解释它代表的核心对象类型、参数的预期行为以及如何安全地管理该类型的对象。

我们使用 `Sphinx <http://www.sphinx-doc.org/en/stable/>`_ 生成 API 文档。Sphinx 支持用 `ReStructured Text <http://openalea.gforge.inria.fr/doc/openalea/doc/_build/html/source/sphinx/rest_syntax.html#auto-document-your-python-code>`_ 编写的文档字符串，并使用特殊的 `关键字 <http://www.sphinx-doc.org/en/stable/domains.html#info-field-lists>`_ 来记录函数和类的参数、返回值、返回类型、成员等。

以下是一个函数文档的示例。理想情况下，参数描述应垂直对齐，以提高文档字符串的可读性。

.. code-block:: python

   def prune(self, filter_func=None, from_stash=None, to_stash=None):
       """
       Prune unsatisfiable paths from a stash.

       :param filter_func: Only prune paths that match this filter.
       :param from_stash:  Prune paths from this stash. (default: 'active')
       :param to_stash:    Put pruned paths in this stash. (default: 'pruned')
       :returns:           The resulting PathGroup.
       :rtype:             PathGroup
       """

这种格式的优点是生成的文档中函数参数的描述非常清晰。但在某些情况下，文字描述可能更简洁易读，可以根据需要选择更适合的格式。例如：

.. code-block:: python

    def read_bytes(self, addr, n):
       """
       Read `n` bytes at address `addr` in memory and return an array of bytes.
       """

单元测试
--------

如果您提交了一个新功能但没有提供测试用例，该功能 **很快就会被破坏**。因此，请为您的代码编写测试用例。

我们有一个内部 CI 服务器，会在每次提交时运行测试，以检查功能和回归情况。为了让我们的服务器运行你的测试，请在适当的仓库的 ``tests`` 文件夹中编写符合 `nosetests <https://nose.readthedocs.org/en/latest/>`_ 接受格式的测试文件，文件名应以 ``test_*.py`` 命名。一个测试文件可以包含任意数量的形式为 ``def test_*():`` 的函数或形式为 ``class Test*(unittest.TestCase):`` 的类。每个函数或类都将作为一个测试运行，如果它们引发任何异常或断言，测试将失败。不要使用 ``nose.tools.assert_*`` 函数，因为我们目前正在尝试迁移到 ``nose2``。使用带有描述性消息的 ``assert`` 语句或 ``unittest.TestCase`` 的断言方法。

查看现有的测试代码作为示例。许多测试使用另一种格式，其中 ``test_*`` 函数实际上是一个生成器，生成要调用的函数及其参数的元组，便于测试的参数化。

最后，不要为测试函数添加文档字符串。