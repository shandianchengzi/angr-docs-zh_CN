符号执行（Symbolic Execution）
==================

符号执行是一种程序分析技术，用于同时探索程序的多个执行路径。与使用特定输入运行程序的正常执行不同，符号执行将输入视为符号变量而不是具体值。这意味着执行可以用符号表达式表示广泛的输入范围。符号执行允许在仿真时确定分支的所有必要条件，以决定是否采取分支。每个变量都表示为符号值，每个分支都表示为约束。因此，符号执行允许我们通过解决这些约束来查看哪些条件允许程序从点A到点B。然后通过解决这些符号表达式生成的约束来分析执行路径，从而发现标准测试中可能遗漏的错误和漏洞。

示例：
--------

考虑以下简单程序：

.. code-block:: c

    const char* check_value(int x) {
        if (x > 10) {
            return "Greater";
        } else {
            return "Lesser or Equal";
        }
    }

在正常执行中，如果 ``x`` 设置为 5，程序将遵循 ``x <= 10`` 的路径并返回 "Lesser or Equal"。在符号执行中， ``x`` 被视为符号变量 ``X``。执行引擎探索两条路径：

   - 路径1： ``X > 10`` 导致结果为 "Greater"
   - 路径2： ``X <= 10`` 导致结果为 "Lesser or Equal"

生成并解决两条路径的约束，以了解程序的所有可能行为。

在软件验证中，它有助于确保代码在所有可能的输入和状态下按预期运行。对于安全分析，符号执行可以发现诸如输入验证错误等漏洞，这些漏洞可能被攻击者利用。此外，在自动化测试中，它有助于生成涵盖边缘情况和罕见执行路径的全面测试用例，从而增强软件系统的健壮性和安全性。总体而言，符号执行提供了一种强大的手段来严格分析和改进软件和固件的可靠性。

基本执行
---------------
现在让我们看看使用 angr 进行符号执行的示例用例。考虑以下示例代码：

.. code-block:: c

    void helloWorld() {
        printf("Hello, World!\n");
    }

    void firstCall(uint32_t num) {
        if (num > 50 && num < 100)
            helloWorld();
    }

``firstCall`` 函数将接受一个 32 位数字作为输入，并在数字在 50 到 100 之间时调用 ``helloWorld`` 函数。

您可以使用以下示例代码执行符号执行，以找到正确且有效的输入，从而达到最终的 ``helloWorld`` 函数调用。

.. code-block:: python

    import angr, claripy
    # 加载二进制文件
    project = angr.Project('./3func', auto_load_libs=False)

    # 定义 firstCall 函数的地址
    firstCall_addr = project.loader.main_object.get_symbol("firstCall")

    # 定义 helloWorld 函数的地址
    helloWorld_addr = project.loader.main_object.get_symbol("helloWorld")
    # 为 firstCall 参数创建一个符号变量
    input_arg = claripy.BVS('input_arg', 32)

    # 在 firstCall 函数的地址创建一个空白状态
    init_state = project.factory.blank_state(addr=firstCall_addr.rebased_addr)

    # 假设调用约定将参数传递到寄存器中
    # （例如，x86 使用 edi 作为参数）
    init_state.regs.edi = input_arg

    # 创建一个仿真管理器
    simgr = project.factory.simulation_manager(init_state)

    # 探索二进制文件，寻找 helloWorld 的地址
    simgr.explore(find=helloWorld_addr.rebased_addr)

    # 检查是否找到达到目标的状态
    if simgr.found:
        input_value = simgr.found[0].solver.eval(input_arg)
        print(f"达到 HelloWorld 的 input_arg 值：{input_value}")
        # 获取达到 helloWorld 函数的约束
        constraints = simgr.found[0].solver.constraints
        # 使用约束创建一个求解器
        solver = claripy.Solver()
        solver.add(constraints)
        min_val = solver.min(input_arg)
        max_val = solver.max(input_arg)
        print(f"函数参数：最小值 = {min_val}, 最大值 = {max_val}")
    else:
        print("未找到达到 HelloWorld 的状态。")

它将生成如下输出，其中包含一个有效的函数参数示例，可以用作测试用例。

.. code-block:: shell

    达到 HelloWorld 的 input_arg 值：71
    函数参数：最小值 = 51, 最大值 = 99