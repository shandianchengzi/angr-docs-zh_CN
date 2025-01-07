使用内置的数据类型和调用约定
=================================

Frequently, you'll want to access structured data from the program you're
analyzing. angr has several features to make this less of a headache.

使用数据类型
------------------

angr 有一个用于表示类型的系统。这些 SimTypes 可以在 ``angr.types`` 中找到 - 这些类的任何实例都表示一种类型。许多类型是不完整的，除非它们被补充了一个 SimState - 它们的大小取决于你运行的架构。你可以使用 ``ty.with_arch(arch)`` 来实现，这将返回一个带有指定架构的自身副本。

angr also has a light wrapper around ``pycparser``, which is a C parser.
This helps with getting instances of type objects:

.. code-block:: python

   >>> import angr, monkeyhex

   # note that SimType objects have their __repr__ defined to return their c type name,
   # so this function actually returned a SimType instance.
   >>> angr.types.parse_type('int')
   int

   >>> angr.types.parse_type('char **')
   char**

   >>> angr.types.parse_type('struct aa {int x; long y;}')
   struct aa

   >>> angr.types.parse_type('struct aa {int x; long y;}').fields
   OrderedDict([('x', int), ('y', long)])

Additionally, you may parse C definitions and have them returned to you in a
dict, either of variable/function declarations or of newly defined types:

.. code-block:: python

   >>> angr.types.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
   {'x': int, 'y': struct llist*}

   >>> defs = angr.types.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
   >>> defs
   {'struct llist': struct llist, 'list_node': struct llist}

   # if you want to get both of these dicts at once, use parse_file, which returns both in a tuple.
   >>> angr.types.parse_file("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
   ({'x': int, 'y': struct llist*},
    {'struct llist': struct llist, 'list_node': struct llist})

   >>> defs['list_node'].fields
   OrderedDict([('str', char*), ('next', struct llist*)])

   >>> defs['list_node'].fields['next'].pts_to.fields
   OrderedDict([('str', char*), ('next', struct llist*)])

   # If you want to get a function type and you don't want to construct it manually,
   # you can use parse_type
   >>> angr.types.parse_type("int (int y, double z)")
   (int, double) -> int

And finally, you can register struct definitions for future use:

.. code-block:: python

   >>> angr.types.register_types(angr.types.parse_type('struct abcd { int x; int y; }'))
   >>> angr.types.register_types(angr.types.parse_types('typedef long time_t;'))
   >>> angr.types.parse_defns('struct abcd a; time_t b;')
   {'a': struct abcd, 'b': long}

These type objects aren't all that useful on their own, but they can be passed
to other parts of angr to specify data types.

Accessing typed data from memory
--------------------------------

Now that you know how angr's type system works, you can unlock the full power of
the ``state.mem`` interface! Any type that's registered with the types module
can be used to extract data from memory.

.. code-block:: python

   >>> p = angr.Project('examples/fauxware/fauxware')
   >>> s = p.factory.entry_state()
   >>> s.mem[0x601048]
   <<untyped> <unresolvable> at 0x601048>

   >>> s.mem[0x601048].long
   <long (64 bits) <BV64 0x4008d0> at 0x601048>

   >>> s.mem[0x601048].long.resolved
   <BV64 0x4008d0>

   >>> s.mem[0x601048].long.concrete
   0x4008d0

   >>> s.mem[0x601048].struct.abcd
   <struct abcd {
     .x = <BV32 0x4008d0>,
     .y = <BV32 0x0>
   } at 0x601048>

   >>> s.mem[0x601048].struct.abcd.x
   <int (32 bits) <BV32 0x4008d0> at 0x601048>

   >>> s.mem[0x601048].struct.abcd.y
   <int (32 bits) <BV32 0x0> at 0x60104c>

   >>> s.mem[0x601048].deref
   <<untyped> <unresolvable> at 0x4008d0>

   >>> s.mem[0x601048].deref.string
   <string_t <BV64 0x534f534e45414b59> at 0x4008d0>

   >>> s.mem[0x601048].deref.string.resolved
   <BV64 0x534f534e45414b59>

   >>> s.mem[0x601048].deref.string.concrete
   b'SOSNEAKY'

The interface works like this:


* You first use [array index notation] to specify the address you'd like to load
  from
* If at that address is a pointer, you may access the ``deref`` property to
  return a SimMemView at the address present in memory.
* You then specify a type for the data by simply accessing a property of that
  name. For a list of supported types, look at ``state.mem.types``.
* You can then *refine* the type. Any type may support any refinement it likes.
  Right now the only refinements supported are that you may access any member of
  a struct by its member name, and you may index into a string or array to
  access that element.
* If the address you specified initially points to an array of that type, you
  can say ``.array(n)`` to view the data as an array of n elements.
* Finally, extract the structured data with ``.resolved`` or ``.concrete``.
  ``.resolved`` will return bitvector values, while ``.concrete`` will return
  integer, string, array, etc values, whatever best represents the data.
* Alternately, you may store a value to memory, by assigning to the chain of
  properties that you've constructed. Note that because of the way Python works,
  ``x = s.mem[...].prop; x = val`` will NOT work, you must say ``s.mem[...].prop
  = val``.

If you define a struct using ``register_types(parse_type(struct_expr))``, you
can access it here as a type:

.. code-block:: python

   >>> s.mem[p.entry].struct.abcd
   <struct abcd {
     .x = <BV32 0x8949ed31>,
     .y = <BV32 0x89485ed1>
   } at 0x400580>

使用调用约定
--------------------------------

调用约定是代码通过函数调用传递参数和返回值的具体方式。angr 的调用约定抽象称为 SimCC。你可以通过 angr 对象工厂构造新的 SimCC 实例，使用 ``p.factory.cc(...)``。这将根据你的目标架构和操作系统猜测一个调用约定。如果 angr 猜错了，你可以在 ``angr.calling_conventions`` 模块中显式选择一个调用约定。

如果你有一个非常奇怪的调用约定，你可以使用 ``angr.calling_conventions.SimCCUsercall``。这将要求你指定参数和返回值的位置。为此，请使用 ``SimRegArg`` 或 ``SimStackArg`` 类的实例。你可以在工厂中找到它们 - ``p.factory.cc.Sim*Arg``。

一旦你有了一个 SimCC 对象，你可以将它与 SimState 对象和函数原型（一个 SimTypeFunction）一起使用，以更清晰地提取或存储函数参数。查看 :py:class:`angr.calling_conventions.SimCC>` 了解详细信息。或者，你可以将它传递给可以使用它来修改其自身行为的接口，例如 ``p.factory.call_state``，或...

Callables
---------

Callables are a Foreign Functions Interface (FFI) for symbolic execution. Basic
callable usage is to create one with ``myfunc = p.factory.callable(addr)``, and
then call it! ``result = myfunc(args, ...)`` When you call the callable, angr
will set up a ``call_state`` at the given address, dump the given arguments into
memory, and run a ``path_group`` based on this state until all the paths have
exited from the function. Then, it merges all the result states together, pulls
the return value out of that state, and returns it.

All the interaction with the state happens with the aid of a ``SimCC`` and a
``SimTypeFunction``, to tell where to put the arguments and where to get the
return value. It will try to use a sane default for the architecture, but if
you'd like to customize it, you can pass a ``SimCC`` object in the ``cc``
keyword argument when constructing the callable. The ``SimTypeFunction`` is
required - you must pass the ``prototype`` parameter. If you pass a string to
this parameter it will be parsed as a function declaration.

You can pass symbolic data as function arguments, and everything will work fine.
You can even pass more complicated data, like strings, lists, and structures as
native Python data (use tuples for structures), and it'll be serialized as
cleanly as possible into the state. If you'd like to specify a pointer to a
certain value, you can wrap it in a ``PointerWrapper`` object, available as
``p.factory.callable.PointerWrapper``. The exact semantics of how
pointer-wrapping work are a little confusing, but they can be boiled down to
"unless you specify it with a PointerWrapper or a specific SimArrayType, nothing
will be wrapped in a pointer automatically unless it gets to the end and it
hasn't yet been wrapped in a pointer yet and the original type is a string,
array, or tuple." The relevant code is actually in SimCC - it's the
``setup_callsite`` function.

If you don't care for the actual return value of the call, you can say
``func.perform_call(arg, ...)``, and then the properties ``func.result_state``
and ``func.result_path_group`` will be populated. They will actually be
populated even if you call the callable normally, but you probably care about
them more in this case!
