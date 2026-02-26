#include "MSG_SOCKET.h"
#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	
#include <wsk.h>


//void TcpListenWorker(void * Context)
//{
//	WSK_SOCKET* paccept_socket = 0;
//	SOCKADDR_IN LocalAddress = { 0 };
//	SOCKADDR_IN RemoteAddress = { 0 };
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//
//	// 创建套接字
//	PWSK_SOCKET TcpSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_LISTEN_SOCKET);
//	if (TcpSocket == NULL)
//	{
//		return;
//	}
//
//	// 设置绑定地址
//	LocalAddress.sin_family = AF_INET;
//	LocalAddress.sin_addr.s_addr = INADDR_ANY;
//	LocalAddress.sin_port = HTON_SHORT(8888);
//
//	status = Bind(TcpSocket, (PSOCKADDR)&LocalAddress);
//	if (!NT_SUCCESS(status))
//	{
//		return;
//	}
//
//	// 循环接收
//	while (1)
//	{
//		CHAR* read_buffer = (CHAR*)ExAllocatePoolWithTag(NonPagedPool, 2048, "read");
//		paccept_socket = Accept(TcpSocket, (PSOCKADDR)&LocalAddress, (PSOCKADDR)&RemoteAddress);
//		if (paccept_socket == NULL)
//		{
//			continue;
//		}
//
//		// 接收数据
//		memset(read_buffer, 0, 2048);
//		int read_len = Receive(paccept_socket, read_buffer, 2048, 0);
//		if (read_len != 0)
//		{
//			DbgPrint("[内核A] => %s \n", read_buffer);
//
//			// 发送数据
//			char send_buffer[2048] = "Hi, lyshark.com B";
//			Send(paccept_socket, send_buffer, strlen(send_buffer), 0);
//
//			// 接收确认包
//			memset(read_buffer, 0, 2048);
//			Receive(paccept_socket, read_buffer, 2, 0);
//		}
//
//		// 清理堆
//		if (read_buffer != NULL)
//		{
//			ExFreePool(read_buffer);
//		}
//
//		// 关闭当前套接字
//		if (paccept_socket)
//		{
//			CloseSocket(paccept_socket);
//		}
//	}
//
//	if (TcpSocket)
//	{
//		CloseSocket(TcpSocket);
//	}
//	PsTerminateSystemThread(STATUS_SUCCESS);
//	return;
//}



// Context structure for each socket
typedef struct _WSK_APP_SOCKET_CONTEXT {
    PWSK_SOCKET Socket;
          // Other application-specific members
} WSK_APP_SOCKET_CONTEXT, * PWSK_APP_SOCKET_CONTEXT;

// Prototype for the socket creation IoCompletion routine
NTSTATUS
CreateListeningSocketComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to create a new listening socket
NTSTATUS CreateListeningSocket(
    PWSK_PROVIDER_NPI WskProviderNpi,
    PWSK_APP_SOCKET_CONTEXT SocketContext,
    PWSK_CLIENT_LISTEN_DISPATCH Dispatch
   )
{
    PIRP Irp;
    NTSTATUS Status;

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        CreateListeningSocketComplete,
        SocketContext,
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the creation of the socket
    Status =
        WskProviderNpi->Dispatch->
        WskSocket(
            WskProviderNpi->Client,
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            WSK_FLAG_LISTEN_SOCKET,
            SocketContext,
            Dispatch,
            NULL,
            NULL,
            NULL,
            Irp
        );

    // Return the status of the call to WskSocket()
    return Status;
}

// Socket creation IoCompletion routine
NTSTATUS
CreateListeningSocketComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_APP_SOCKET_CONTEXT SocketContext;

    // Check the result of the socket creation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the pointer to the socket context
        SocketContext =
            (PWSK_APP_SOCKET_CONTEXT)Context;

        // Save the socket object for the new socket
        SocketContext->Socket =
            (PWSK_SOCKET)(Irp->IoStatus.Information);

        // Set any socket options for the new socket
        // 
            // Enable any event callback functions on the new socket


            // Perform any other initializations

    }
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}




// Prototype for the accept IoCompletion routine
NTSTATUS
AcceptComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to accept an incoming connection
NTSTATUS
AcceptConnection(
    PWSK_SOCKET Socket,
    PVOID AcceptSocketContext,
    PWSK_CLIENT_CONNECTION_DISPATCH AcceptSocketDispatch
)
{
    PWSK_PROVIDER_LISTEN_DISPATCH Dispatch;
    PIRP Irp;
    NTSTATUS Status;

    // Get pointer to the socket's provider dispatch structure
    Dispatch =
        (PWSK_PROVIDER_LISTEN_DISPATCH)(Socket->Dispatch);

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        AcceptComplete,
        AcceptSocketContext,
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the accept operation on the socket
    Status =
        Dispatch->WskAccept(
            Socket,
            0,  // No flags
            AcceptSocketContext,
            AcceptSocketDispatch,
            NULL,
            NULL,
            Irp
        );

    // Return the status of the call to WskAccept()
    return Status;
}

// The accept IoCompletion routine
NTSTATUS
AcceptComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_SOCKET Socket;
    PVOID AcceptSocketContext;

    // Check the result of the accept operation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the accepted socket object from the IRP
        Socket = (PWSK_SOCKET)(Irp->IoStatus.Information);

        // Get the accepted socket's context
        AcceptSocketContext = Context;

        // Perform the next operation on the accepted socket
    }

    // Error status
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}


// Prototype for the bind IoCompletion routine
NTSTATUS
BindComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to bind a listening socket to a local transport address
NTSTATUS
BindListeningSocket(
    PWSK_SOCKET Socket,
    PSOCKADDR LocalAddress
)
{
    PWSK_PROVIDER_LISTEN_DISPATCH Dispatch;
    PIRP Irp;
    NTSTATUS Status;

    // Get pointer to the socket's provider dispatch structure
    Dispatch =
        (PWSK_PROVIDER_LISTEN_DISPATCH)(Socket->Dispatch);

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        BindComplete,
        Socket,  // Use the socket object for the context
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the bind operation on the socket
    Status =
        Dispatch->WskBind(
            Socket,
            LocalAddress,
            0,  // No flags
            Irp
        );

    // Return the status of the call to WskBind()
    return Status;
}

// Bind IoCompletion routine
NTSTATUS
BindComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_SOCKET Socket;

    // Check the result of the bind operation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the socket object from the context
        Socket = (PWSK_SOCKET)Context;

        // Perform the next operation on the socket
    }

    // Error status
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}



// Prototype for the socket close IoCompletion routine
NTSTATUS
CloseSocketComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to close a socket
NTSTATUS
CloseSocket(
    PWSK_SOCKET Socket,
    PWSK_APP_SOCKET_CONTEXT SocketContext
)
{
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch;
    PIRP Irp;
    NTSTATUS Status;

    // Get pointer to the socket's provider dispatch structure
    Dispatch =
        (PWSK_PROVIDER_BASIC_DISPATCH)(Socket->Dispatch);

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        CloseSocketComplete,
        SocketContext,
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the close operation on the socket
    Status =
        Dispatch->WskCloseSocket(
            Socket,
            Irp
        );

    // Return the status of the call to WskCloseSocket()
    return Status;
}

// Socket close IoCompletion routine
NTSTATUS
CloseSocketComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_APP_SOCKET_CONTEXT SocketContext;

    // Check the result of the socket close operation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the pointer to the socket context
        SocketContext =
            (PWSK_APP_SOCKET_CONTEXT)Context;

        // Perform any cleanup and/or deallocation of the socket context
    }

    // Error status
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}


//-----------------------------------------------------------------



const WSK_CLIENT_DISPATCH WskAppDispatch = {
  MAKE_WSK_VERSION(1,0), // Use WSK version 1.0
  0,    // Reserved
  NULL  // WskClientEvent callback not required for WSK version 1.0
};

// WSK Registration object
WSK_REGISTRATION WskRegistration;

// DriverEntry function
NTSTATUS
WskBegin()
{
    NTSTATUS Status;
    WSK_CLIENT_NPI wskClientNpi;
        // Register the WSK application
    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &WskAppDispatch;
    Status = WskRegister(&wskClientNpi, &WskRegistration);
    return Status;
}





// Prototype for the send IoCompletion routine
NTSTATUS
SendComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to send data
NTSTATUS
SendData(
    PWSK_SOCKET Socket,
    PWSK_BUF DataBuffer
)
{
    PWSK_PROVIDER_CONNECTION_DISPATCH Dispatch;
    PIRP Irp;
    NTSTATUS Status;

    // Get pointer to the provider dispatch structure
    Dispatch =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)(Socket->Dispatch);

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        SendComplete,
        DataBuffer,  // Use the data buffer for the context
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the send operation on the socket
    Status =
        Dispatch->WskSend(
            Socket,
            DataBuffer,
            0,  // No flags
            Irp
        );

    // Return the status of the call to WskSend()
    return Status;
}

// Send IoCompletion routine
NTSTATUS
SendComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_BUF DataBuffer;
    ULONG ByteCount;

    // Check the result of the send operation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the pointer to the data buffer
        DataBuffer = (PWSK_BUF)Context;

        // Get the number of bytes sent
        ByteCount = (ULONG)(Irp->IoStatus.Information);

        // Re-use or free the data buffer
    }

    // Error status
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}








// Prototype for the receive IoCompletion routine
NTSTATUS
ReceiveComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
);

// Function to receive data
NTSTATUS
ReceiveData(
    PWSK_SOCKET Socket,
    PWSK_BUF DataBuffer
)
{
    PWSK_PROVIDER_CONNECTION_DISPATCH Dispatch;
    PIRP Irp;
    NTSTATUS Status;

    // Get pointer to the provider dispatch structure
    Dispatch =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)(Socket->Dispatch);

    // Allocate an IRP
    Irp =
        IoAllocateIrp(
            1,
            FALSE
        );

    // Check result
    if (!Irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(
        Irp,
        ReceiveComplete,
        DataBuffer,  // Use the data buffer for the context
        TRUE,
        TRUE,
        TRUE
    );

    // Initiate the receive operation on the socket
    Status =
        Dispatch->WskReceive(
            Socket,
            DataBuffer,
            0,  // No flags are specified
            Irp
        );

    // Return the status of the call to WskReceive()
    return Status;
}

// Receive IoCompletion routine
NTSTATUS
ReceiveComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PWSK_BUF DataBuffer;
    ULONG ByteCount;

    // Check the result of the receive operation
    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        // Get the pointer to the data buffer
        DataBuffer = (PWSK_BUF)Context;

        // Get the number of bytes received
        ByteCount = (ULONG)(Irp->IoStatus.Information);

        // Process the received data
    }

    // Error status
    else
    {
        // Handle error
    }

    // Free the IRP
    IoFreeIrp(Irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}