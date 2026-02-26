#include "Except.h"





//VOID
//KiDispatchException(
//    IN PEXCEPTION_RECORD ExceptionRecord,
//    IN PKEXCEPTION_FRAME ExceptionFrame,
//    IN PKTRAP_FRAME TrapFrame,
//    IN KPROCESSOR_MODE PreviousMode,
//    IN BOOLEAN FirstChance
//)
//
///*++
//
//// 异常派发函数
//// 派发一个异常到适当的模式
//// ps.
//// 调试本身流程是经过 KiDispatchException 而不是 KiDispatchInterrupt
//// KiDispatchInterrupt 主要功能为处理外部中断，时钟，鼠键等,若分析定时器等实现需要跟入该函数实现
//
//// 如果中断发生前 处于内核模式，将直接处理该异常，否则把异常信息包装抛出到用户模式(涉及跨级别的内存拷贝)
//
//
//Routine Description:
//
//    This function is called to dispatch an exception to the proper mode and
//    to cause the exception dispatcher to be called. If the previous mode is
//    kernel, then the exception dispatcher is called directly to process the
//    exception. Otherwise the exception record, exception frame, and trap
//    frame contents are copied to the user mode stack. The contents of the
//    exception frame and trap are then modified such that when control is
//    returned, execution will commense in user mode in a routine which will
//    call the exception dispatcher.
//
//Arguments:
//
//    // 异常记录的指针
//    ExceptionRecord - Supplies a pointer to an exception record.
//
//    // 指向异常帧，在 NT386 模式下 该指针为 NULL
//    ExceptionFrame - Supplies a pointer to an exception frame. For NT386,
//        this should be NULL.
//
//    // 指向陷阱帧
//    TrapFrame - Supplies a pointer to a trap frame.
//
//    // 前一个模式, 在中断发生之前系统所处的模式
//    PreviousMode - Supplies the previous processor mode.
//
//    // 是否是第一次机会异常
//    FirstChance - Supplies a boolean value that specifies whether this is
//        the first (TRUE) or second (FALSE) chance for the exception.
//
//Return Value:
//
//    None.
//
//--*/
//
//{
//    CONTEXT ContextFrame;
//    EXCEPTION_RECORD ExceptionRecord1, ExceptionRecord2;
//    LONG Length;
//    ULONG UserStack1;
//    ULONG UserStack2;
//
//    //
//    // Move machine state from trap and exception frames to a context frame,
//    // and increment the number of exceptions dispatched.
//    //
//
//    // 增加异常派发计数
//    KeGetCurrentPrcb()->KeExceptionDispatchCount += 1;
//    // 设置上下文帧需要记录的内容标志
//    // SS:SP, CS:IP, FLAGS, BP
//    // AX, BX, CX, DX, SI, DI
//    // DS, ES, FS, GS
//    // DB 0-3,6,7
//
//    ContextFrame.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
//
//    // 如果之前处于用户程序，且处于调试模式,需要对 ContextFrame 进行包装
//    if ((PreviousMode == UserMode) || KdDebuggerEnabled) {
//        // 为了处理一些特殊情况 (80387处理器 的npx支持) 而特别需要加上的标志
//        //
//        // For usermode exceptions always try to dispatch the floating
//        // point state.  This allows exception handlers & debuggers to
//        // examine/edit the npx context if required.  Plus it allows
//        // exception handlers to use fp instructions without destroying
//        // the npx state at the time of the exception.
//        //
//        // Note: If there's no 80387, ContextTo/FromKFrames will use the
//        // emulator's current state.  If the emulator can not give the
//        // current state, then the context_floating_point bit will be
//        // turned off by ContextFromKFrames.
//        //
//
//        ContextFrame.ContextFlags |= CONTEXT_FLOATING_POINT;
//        if (KeI386XMMIPresent) {
//            ContextFrame.ContextFlags |= CONTEXT_EXTENDED_REGISTERS;
//        }
//    }
//
//    // 根据所设置的标志位从 陷阱帧中取出相应的寄存器数据 加入 上下文帧
//    // 注意 这里并未使用异常帧
//    KeContextFromKframes(TrapFrame, ExceptionFrame, &ContextFrame);
//
//    //
//    // if it is BREAK_POINT exception, we subtract 1 from EIP and report
//    // the updated EIP to user.  This is because Cruiser requires EIP
//    // points to the int 3 instruction (not the instruction following int 3).
//    // In this case, BreakPoint exception is fatal. Otherwise we will step
//    // on the int 3 over and over again, if user does not handle it
//    //
//    // if the BREAK_POINT occured in V86 mode, the debugger running in the
//    // VDM will expect CS:EIP to point after the exception (the way the
//    // processor left it.  this is also true for protected mode dos
//    // app debuggers.  We will need a way to detect this.
//    //
//    //
//
//    // 如果是 int 3 造成的异常，eip需要减一之后传递给用户层,,
//    switch (ExceptionRecord->ExceptionCode) {
//    case STATUS_BREAKPOINT:
//        ContextFrame.Eip--;
//        break;
//
//        // 应用层无效的访问或访问越界
//    case KI_EXCEPTION_ACCESS_VIOLATION:
//        ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
//        if (PreviousMode == UserMode) {
//            if (KiCheckForAtlThunk(ExceptionRecord, &ContextFrame) != FALSE) {
//                goto Handled1;
//            }
//
//            if ((SharedUserData->ProcessorFeatures[PF_NX_ENABLED] == TRUE) &&
//                (ExceptionRecord->ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT)) {
//
//                if (((KeFeatureBits & KF_GLOBAL_32BIT_EXECUTE) != 0) ||
//                    (PsGetCurrentProcess()->Pcb.Flags.ExecuteEnable != 0) ||
//                    (((KeFeatureBits & KF_GLOBAL_32BIT_NOEXECUTE) == 0) &&
//                        (PsGetCurrentProcess()->Pcb.Flags.ExecuteDisable == 0))) {
//                    ExceptionRecord->ExceptionInformation[0] = 0;
//                }
//            }
//        }
//        break;
//    }
//
//    //
//    // Select the method of handling the exception based on the previous mode.
//    //
//
//    ASSERT((
//        !((PreviousMode == KernelMode) &&
//            (ContextFrame.EFlags & EFLAGS_V86_MASK))
//        ));
//
//    // 当之前的模式处于内核模式
//    if (PreviousMode == KernelMode) {
//
//        //
//        // 首先判断 内核调试器是否存在，如果内核调试器存在，给予内核调试第一轮处理机会
//        // 如果内核调试器处理异常，将继续运行。
//        // 如果内核调试器不能处理，交给异常的处理框架处理。
//        // 如果框架能处理则继续运行。
//        // 如果处理框架也不能处理，给予内核调试器第二次处理机会，如果不能处理 KeBugCheck,给个蓝脸
//        //
//
//        // ps.
//        // 故 KiDebugRoutine 是检查当前系统是否处于调试状态的一个点
//
//        //
//        // Previous mode was kernel.
//        //
//        // If the kernel debugger is active, then give the kernel debugger the
//        // first chance to handle the exception. If the kernel debugger handles
//        // the exception, then continue execution. Else attempt to dispatch the
//        // exception to a frame based handler. If a frame based handler handles
//        // the exception, then continue execution.
//        //
//        // If a frame based handler does not handle the exception,
//        // give the kernel debugger a second chance, if it's present.
//        //
//        // If the exception is still unhandled, call KeBugCheck().
//        //
//
//        if (FirstChance == TRUE) {
//
//            if ((KiDebugRoutine != NULL) &&
//                (((KiDebugRoutine)(TrapFrame,
//                    ExceptionFrame,
//                    ExceptionRecord,
//                    &ContextFrame,
//                    PreviousMode,
//                    FALSE)) != FALSE)) {
//
//                goto Handled1;
//            }
//
//            // Kernel debugger didn't handle exception.  所以 实际上 异常处理框架只有一次处理机会
//
//            if (RtlDispatchException(ExceptionRecord, &ContextFrame) == TRUE) {
//                goto Handled1;
//            }
//        }
//
//        //
//        // This is the second chance to handle the exception.
//        //
//
//        if ((KiDebugRoutine != NULL) &&
//            (((KiDebugRoutine)(TrapFrame,
//                ExceptionFrame,
//                ExceptionRecord,
//                &ContextFrame,
//                PreviousMode,
//                TRUE)) != FALSE)) {
//
//            goto Handled1;
//        }
//
//        KeBugCheckEx(
//            KERNEL_MODE_EXCEPTION_NOT_HANDLED,
//            ExceptionRecord->ExceptionCode,
//            (ULONG)ExceptionRecord->ExceptionAddress,
//            (ULONG)TrapFrame,
//            0);
//
//    }
//    else {
//
//        // 如果当前处于用户模式
//
//        // 如果这是第一次处理机会且当前进程存在调试端口，发送消息到调试端口并等待回应。
//        // 如果调试器处理异常，继续执行。
//        //
//        // 如果不存在调试器，则拷贝异常信息到用户栈，交由用户层的异常处理框架处理。
//        // 如果处理框架能够处理，则继续执行。
//        // 如果是调用的 NtRaiseException 自行抛出的异常且不接收第一次处理机会
//        // 那么它将在第二次调用的时候才有机会处理
//
//        // 如果这是第二次机会，并且当前进程存在调试端口，还是优先发往调试端口
//        // 否则则发往子系统端口，如果子系统端口不能处理，结束进程
//
//        // Previous mode was user.
//        //
//        // If this is the first chance and the current process has a debugger
//        // port, then send a message to the debugger port and wait for a reply.
//        // If the debugger handles the exception, then continue execution. Else
//        // transfer the exception information to the user stack, transition to
//        // user mode, and attempt to dispatch the exception to a frame based
//        // handler. If a frame based handler handles the exception, then continue
//        // execution with the continue system service. Else execute the
//        // NtRaiseException system service with FirstChance == FALSE, which
//        // will call this routine a second time to process the exception.
//        //
//        // If this is the second chance and the current process has a debugger
//        // port, then send a message to the debugger port and wait for a reply.
//        // If the debugger handles the exception, then continue execution. Else
//        // if the current process has a subsystem port, then send a message to
//        // the subsystem port and wait for a reply. If the subsystem handles the
//        // exception, then continue execution. Else terminate the process.
//        //
//
//        if (FirstChance == TRUE) {
//
//            //
//            // This is the first chance to handle the exception.
//            //
//            // 优先交给内核调试器处理
//            if ((KiDebugRoutine != NULL) &&
//                ((PsGetCurrentProcess()->DebugPort == NULL &&
//                    !KdIgnoreUmExceptions) ||
//                    (KdIsThisAKdTrap(ExceptionRecord, &ContextFrame, UserMode)))) {
//                //
//                // Now dispatch the fault to the kernel debugger.
//                //
//
//                if ((((KiDebugRoutine)(TrapFrame,
//                    ExceptionFrame,
//                    ExceptionRecord,
//                    &ContextFrame,
//                    PreviousMode,
//                    FALSE)) != FALSE)) {
//
//                    goto Handled1;
//                }
//            }
//
//            // 发往调试端口和异常端口(子系统端口)
//            if (DbgkForwardException(ExceptionRecord, TRUE, FALSE)) {
//                goto Handled2;
//            }
//
//            //
//            // Transfer exception information to the user stack, transition
//            // to user mode, and attempt to dispatch the exception to a frame
//            // based handler.
//
//            ExceptionRecord1.ExceptionCode = 0; // satisfy no_opt compilation
//
//            // 拷贝异常信息到用户栈上  
//        repeat:
//            try {
//
//                //
//                // If the SS segment is not 32 bit flat, there is no point
//                // to dispatch exception to frame based exception handler.
//                //
//
//                if (TrapFrame->HardwareSegSs != (KGDT_R3_DATA | RPL_MASK) ||
//                    TrapFrame->EFlags & EFLAGS_V86_MASK) {
//                    ExceptionRecord2.ExceptionCode = STATUS_ACCESS_VIOLATION;
//                    ExceptionRecord2.ExceptionFlags = 0;
//                    ExceptionRecord2.NumberParameters = 0;
//                    ExRaiseException(&ExceptionRecord2);
//                }
//
//                //
//                // Compute length of context record and new aligned user stack
//                // pointer.
//                //
//
//                UserStack1 = (ContextFrame.Esp & ~CONTEXT_ROUND) - CONTEXT_ALIGNED_SIZE;
//
//                //
//                // Probe user stack area for writability and then transfer the
//                // context record to the user stack.
//                //
//
//                ProbeForWrite((PCHAR)UserStack1, CONTEXT_ALIGNED_SIZE, CONTEXT_ALIGN);
//                RtlCopyMemory((PULONG)UserStack1, &ContextFrame, sizeof(CONTEXT));
//
//                //
//                // Compute length of exception record and new aligned stack
//                // address.
//                //
//
//                Length = (sizeof(EXCEPTION_RECORD) - (EXCEPTION_MAXIMUM_PARAMETERS -
//                    ExceptionRecord->NumberParameters) * sizeof(ULONG) + 3) &
//                    (~3);
//                UserStack2 = UserStack1 - Length;
//
//                //
//                // Probe user stack area for writeability and then transfer the
//                // context record to the user stack area.
//                // N.B. The probing length is Length+8 because there are two
//                //      arguments need to be pushed to user stack later.
//                //
//
//                ProbeForWrite((PCHAR)(UserStack2 - 8), Length + 8, sizeof(ULONG));
//                RtlCopyMemory((PULONG)UserStack2, ExceptionRecord, Length);
//
//                //
//                // Push address of exception record, context record to the
//                // user stack.  They are the two parameters required by
//                // _KiUserExceptionDispatch.
//                //
//
//                *(PULONG)(UserStack2 - sizeof(ULONG)) = UserStack1;
//                *(PULONG)(UserStack2 - 2 * sizeof(ULONG)) = UserStack2;
//
//                //
//                // Set new stack pointer to the trap frame.
//                //
//
//                KiSegSsToTrapFrame(TrapFrame, KGDT_R3_DATA);
//                KiEspToTrapFrame(TrapFrame, (UserStack2 - sizeof(ULONG) * 2));
//
//                //
//                // Force correct R3 selectors into TrapFrame.
//                //
//
//                TrapFrame->SegCs = SANITIZE_SEG(KGDT_R3_CODE, PreviousMode);
//                TrapFrame->SegDs = SANITIZE_SEG(KGDT_R3_DATA, PreviousMode);
//                TrapFrame->SegEs = SANITIZE_SEG(KGDT_R3_DATA, PreviousMode);
//                TrapFrame->SegFs = SANITIZE_SEG(KGDT_R3_TEB, PreviousMode);
//                TrapFrame->SegGs = 0;
//
//                //
//                // Set the address of the exception routine that will call the
//                // exception dispatcher and then return to the trap handler.
//                // The trap handler will restore the exception and trap frame
//                // context and continue execution in the routine that will
//                // call the exception dispatcher.
//                //
//
//                TrapFrame->Eip = (ULONG)KeUserExceptionDispatcher;
//                return;
//
//            } except(KiCopyInformation(&ExceptionRecord1,
//                (GetExceptionInformation())->ExceptionRecord)) {
//
//                //
//                // If the exception is a stack overflow, then attempt
//                // to raise the stack overflow exception. Otherwise,
//                // the user's stack is not accessible, or is misaligned,
//                // and second chance processing is performed.
//                //
//
//                if (ExceptionRecord1.ExceptionCode == STATUS_STACK_OVERFLOW) {
//                    ExceptionRecord1.ExceptionAddress = ExceptionRecord->ExceptionAddress;
//                    RtlCopyMemory((PVOID)ExceptionRecord,
//                        &ExceptionRecord1, sizeof(EXCEPTION_RECORD));
//                    goto repeat;
//                }
//            }
//        }
//
//        //
//        // This is the second chance to handle the exception.
//        //
//
//        if (DbgkForwardException(ExceptionRecord, TRUE, TRUE)) {
//            goto Handled2;
//        }
//        else if (DbgkForwardException(ExceptionRecord, FALSE, TRUE)) {
//            goto Handled2;
//        }
//        else {
//            ZwTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
//            KeBugCheckEx(
//                KERNEL_MODE_EXCEPTION_NOT_HANDLED,
//                ExceptionRecord->ExceptionCode,
//                (ULONG)ExceptionRecord->ExceptionAddress,
//                (ULONG)TrapFrame,
//                0);
//        }
//    }
//
//    //
//    // Move machine state from context frame to trap and exception frames and
//    // then return to continue execution with the restored state.
//    //
//
//Handled1:
//    // 还原上下文到陷阱帧
//    KeContextToKframes(TrapFrame, ExceptionFrame, &ContextFrame,
//        ContextFrame.ContextFlags, PreviousMode);
//
//    //
//    // Exception was handled by the debugger or the associated subsystem
//    // and state was modified, if necessary, using the get state and set
//    // state capabilities. Therefore the context frame does not need to
//    // be transferred to the trap and exception frames.
//    //
//
//Handled2:
//    return;
//}