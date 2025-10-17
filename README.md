# ReflectiveDLL

反射DLL是一种高级的DLL加载技术，它通过模拟Windows加载器的工作流程，实现了从内存中直接加载DLL。

原项目：oldboy21/RflDllOb

## 介绍

**注入器**

注入器首先读取DLL文件到内存空间中，并加密某些函数。它会根据程序文件找到PID。通过`OpenProcess`获得进程的句柄，向目标进程申请一块新的内存空间（大小为反射DLL的大小 + 自定义头部大小），并使用`WriteProcessMemory`将头部({ 魔术值，KEY，反射函数大小 }）写入到目标进程的内存空间中。最后注入器创建一个远程线程，线程的起始函数为反射DLL中导出的预加载函数。

**反射DLL**

注入器会创建一个线程执行预加载函数，预加载函数会通过`RIP`寄存器获取当前模块的DLL头部（通过魔数头，反射DLL模块紧随着自定义的DLL头部）。当确定好模块基地址之后，预加载函数会根据头部的KEY来解密反射函数，执行反射函数之后并重新加密。最后创建新的线程执行`DllMain`函数。

反射函数通过对`ZwClose` ，`NtMapViewOfSection` 和 `NtCreateSection` 函数的入口打上硬件断点，并注册一个向量化异常处理例程，当触发单步异常时（如硬件断点），该异常处理例程就会被执行。异常处理例程通过调用这些API的`detour function` 对传入的参数进行修改。反射函数使用`LoadLibraryEx`加载牺牲的DLL(`SRH.dll`)，由于`LoadLibraryEx`会调用我们之前设置断点的几个API函数，所以当这些函数被`LoadLibraryEx`函数调用时，我们的异常处理例程就可以捕获这些单步异常，并调用对应的`detour function`去修改参数。`LoadLibraryEx`会对加载的DLL创建一个`Section`对象，并在最后通过`ZwClose`函数关闭这个对象。我们使用`ZwCloseDetour`函数来跳过该函数，保留该对象。当`LoadLibraryEx`函数执行完毕，我们移除该向量化异常处理例程，并取消这些硬件断点，最后获得`SRH.dll`的`Section`对象的句柄。

反射函数也通过`RIP`寄存器获取当前模块的DLL头部，并使用`mem_to_free`变量记录该地址（由于我们之前通过`VirtualAllocEx`函数申请了这块内存，后续我们需要释放这块内存避免内存泄漏）。

反射函数创建一个新的`Section`对象，其大小稍大于`SRH.dll`的大小（因为我们需要额外记录某些信息）。紧接着，它会取消映射由`LoadLibraryEx`函数映射的`SRH.dll`的视图，记录该模块的基地址，并在该基地址处重新映射我们刚刚创建的`Section`对象的视图。

我们记录牺牲的DLL(SRH.dll)的Section句柄，刚刚创建的Section句柄，以及新创建的Section大小和mem_to_free，将这些信息放在基地址头部。紧接着拷贝反射DLL的信息到刚刚新建的Section中。
