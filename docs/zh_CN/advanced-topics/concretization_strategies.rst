内存寻址符号化（Symbolic memory addressing）
==========================

angr 支持 *符号内存寻址* ，这意味着内存偏移量可以是符号的。我们的实现灵感来自 "Mayhem"。具体来说，这意味着 angr 在符号地址被用作写入目标时会将其具体化。这会引起一些意外，因为用户往往期望符号写入被纯粹地符号化处理，或者像我们处理符号读取一样“符号化”，但这不是默认行为。然而，像 angr 中的大多数事情一样，这是可配置的。

The address resolution behavior is governed by *concretization strategies*,
which are subclasses of
``angr.concretization_strategies.SimConcretizationStrategy``. Concretization
strategies for reads are set in ``state.memory.read_strategies`` and for writes
in ``state.memory.write_strategies``. These strategies are called, in order,
until one of them is able to resolve addresses for the symbolic index. By
setting your own concretization strategies (or through the use of SimInspect
``address_concretization`` breakpoints, described above), you can change the way
angr resolves symbolic addresses.

For example, angr's default concretization strategies for writes are:


#. A conditional concretization strategy that allows symbolic writes (with a
   maximum range of 128 possible solutions) for any indices that are annotated
   with ``angr.plugins.symbolic_memory.MultiwriteAnnotation``.
#. A concretization strategy that simply selects the maximum possible solution
   of the symbolic index.

To enable symbolic writes for all indices, you can either add the
``SYMBOLIC_WRITE_ADDRESSES`` state option at state creation time or manually
insert a ``angr.concretization_strategies.SimConcretizationStrategyRange``
object into ``state.memory.write_strategies``. The strategy object takes a
single argument, which is the maximum range of possible solutions that it allows
before giving up and moving on to the next (presumably non-symbolic) strategy.

Writing concretization strategies
---------------------------------

.. todo:: Write this section
