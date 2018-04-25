Imports System.Runtime.InteropServices
Imports System.Text

Module Module1
    Public m_BaseAddress As IntPtr
    Public m_Process As Process
    Public m_MainWindowsHandle As IntPtr
    Public m_iNumberOfBytesRead As Integer = 0
    Public m_pProcessHandle As IntPtr

    <DllImport("kernel32.dll")>
    Public Function OpenProcess(ByVal dwDesiredAccess As Integer, ByVal bInheritHandle As Boolean, ByVal dwProcessId As Integer) As IntPtr
    End Function

    <DllImport("kernel32.dll")>
    Public Function ReadProcessMemory(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal buffer As Byte(), ByVal size As Integer, ByRef lpNumberOfBytesRead As Integer) As Boolean
    End Function

    <DllImport("kernel32.dll")>
    Public Function WriteProcessMemory(ByVal hProcess As IntPtr, ByVal lpBaseAddress As IntPtr, ByVal buffer As Byte(), ByVal size As Integer, ByRef lpNumberOfBytesWritten As Integer) As Boolean
    End Function

    Private Function ByteArrayToStructure(Of T As Structure)(ByVal bytes As Byte()) As T
        Dim local As T
        Dim handle As GCHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned)
        Try
            local = DirectCast(Marshal.PtrToStructure(handle.AddrOfPinnedObject, GetType(T)), T)
        Finally
            handle.Free()
        End Try
        Return local
    End Function

    Public Function ReadMemory(Of T As Structure)(ByVal Adress As IntPtr) As T
        Dim buffer As Byte() = New Byte(Marshal.SizeOf(GetType(T)) - 1) {}
        ReadProcessMemory(m_pProcessHandle, Adress, buffer, buffer.Length, m_iNumberOfBytesRead)
        Return ByteArrayToStructure(Of T)(buffer)
    End Function


    Public Const Client As Integer = &H20E8590
    Public Function Initialize(ByVal ProcessName As String) As Boolean
        If (Process.GetProcessesByName(ProcessName).Length > 0) Then
            Threading.Thread.Sleep(1000)
            m_Process = Process.GetProcessesByName(ProcessName)(0)
            m_BaseAddress = m_Process.MainModule.BaseAddress
            m_MainWindowsHandle = m_Process.MainWindowHandle

            m_pProcessHandle = OpenProcess(56, False, m_Process.Id)
            Return True
        End If
        Return False
    End Function

    Public buffer As Byte()
    Public Function ReadString(ByVal address As IntPtr, ByVal _Size As Integer) As String
        If _Size > 0 And _Size < 256 Then
            Buffer = New Byte(_Size - 1) {}
            ReadProcessMemory(m_pProcessHandle, address, buffer, _Size, m_iNumberOfBytesRead)
            Dim sb As New StringBuilder(Encoding.UTF8.GetString(buffer))
            For index As Integer = 0 To _Size - 1
                Try
                    If AscW(sb(index)) = 0 Then
                        sb.Length = index
                        Exit For
                    End If
                Catch ex As Exception
                    Exit For
                End Try


                If Char.IsControl(sb(index)) Then
                    sb(index) = "."
                End If
            Next
            Return sb.ToString
        End If
        Return ""
    End Function

    Public Function GetEntry(Of T As Structure)(ByVal baseEntry As IntPtr, ByVal entryId As Integer) As T
        Return ReadMemory(Of T)(ReadMemory(Of IntPtr)(baseEntry + (&HC * entryId) + &H8) + &H8)
    End Function

    Public Sub GetEntryList(ByVal pEntity As IntPtr)
        Dim meta = ReadMemory(Of IntPtr)(pEntity + &H4)
        Dim table = ReadMemory(Of IntPtr)(pEntity + &H120)
        Dim tableCount = ReadMemory(Of Integer)(table + &HC)
        Dim firstEntry = ReadMemory(Of IntPtr)(table + &H14)
        Dim meta_name_str As String = ReadString(ReadMemory(Of Integer)(meta + &HC), 40)
        'Console.WriteLine("Entry count: {0}", tableCount
        If tableCount > 0 And tableCount < 1000 Then
            If Not IO.File.Exists(meta_name_str & ".txt") Then
                Dim txtFile As New IO.StreamWriter(meta_name_str & ".txt")
                Console.WriteLine("Meta: {0}[0x{1:X}]", meta_name_str, firstEntry.ToInt32)
                For index As Integer = 0 To tableCount - 1

                    Dim entry As IntPtr = firstEntry + (index * 12)
                    Dim entry_name As IntPtr = ReadMemory(Of IntPtr)(entry + &H4)
                    Dim entry_data As IntPtr = ReadMemory(Of IntPtr)(entry + &H8)

                    Dim entry_size As Integer = ReadMemory(Of Integer)(entry_name + &H8)
                    Dim entry_name_str As String = ReadString(entry_name + &H14, entry_size)

                    Dim data_type As IntPtr = ReadMemory(Of IntPtr)(entry_data + &H4)
                    Dim data_type_name As IntPtr = ReadMemory(Of IntPtr)(data_type + &HC)
                    Dim data_type_name1 As IntPtr = ReadMemory(Of IntPtr)(data_type_name)
                    Dim data_type_name_str As String = ReadString(data_type_name, 40)

                    If data_type_name_str = "str" Then
                        Dim data_value = ReadMemory(Of Integer)(entry_data + &H8)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}[{5}]", index, (index * 12) + 8, entry_name_str, data_type_name_str, ReadString(entry_data + &H14, data_value), data_value)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}[{5}]", index, (index * 12) + 8, entry_name_str, data_type_name_str, ReadString(entry_data + &H14, data_value), data_value)
                    ElseIf data_type_name_str = "int" Then
                        Dim data_value = ReadMemory(Of Integer)(entry_data + &H8)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                        'Console.WriteLine("  |-value[0x8]: {0}", data_value)
                    ElseIf data_type_name_str = "bool" Then
                        Dim data_value = ReadMemory(Of Boolean)(entry_data + &H8)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                    ElseIf data_type_name_str = "float" Then
                        Dim data_value = ReadMemory(Of Single)(entry_data + &HC)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4:0.00##}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4:0.00##}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                    ElseIf data_type_name_str = "list" Then
                        Dim data_value = ReadMemory(Of IntPtr)(entry_data + &HC)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                    ElseIf data_type_name_str = "long" Then
                        Dim data_value = ReadMemory(Of Long)(entry_data + &H8)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> {4}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value)
                    ElseIf data_type_name_str = "dict" Then
                        Dim data_value = ReadMemory(Of IntPtr)(entry_data + &H14)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                    ElseIf data_type_name_str = "NoneType" Then
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}>", index, (index * 12) + 8, entry_name_str, data_type_name_str)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}>", index, (index * 12) + 8, entry_name_str, data_type_name_str)
                    ElseIf data_type_name_str = "Math.Vector3" Then
                        Dim data_value = ReadMemory(Of Vect3)(entry_data + &HC)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}, z={6}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y, data_value.Z)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}, z={6}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y, data_value.Z)
                    ElseIf data_type_name_str = "Math.Vector2" Then
                        Dim data_value = ReadMemory(Of Vect2)(entry_data + &HC)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y)
                    ElseIf data_type_name_str = "Math.Vector4" Then
                        Dim data_value = ReadMemory(Of Vect4)(entry_data + &HC)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}, w={6}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y, data_value.W)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> x={4}, y={5}, w={6}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.X, data_value.Y, data_value.W)
                    ElseIf data_type_name_str = "CampInfo" Then
                        Dim data_value = ReadMemory(Of IntPtr)(entry_data + &H14)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                    ElseIf data_type_name_str = "Vector3" Then
                        Dim data_value = ReadMemory(Of IntPtr)(entry_data + &H14)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                    Else
                        Dim data_value = ReadMemory(Of IntPtr)(entry_data + &H8)
                        Console.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                        txtFile.WriteLine("[{0,3}][0x{1:X4}] {2}: <{3}> 0x{4:X}", index, (index * 12) + 8, entry_name_str, data_type_name_str, data_value.ToInt32)
                    End If
                    'Console.WriteLine("--------------------------------------------")
                Next
                txtFile.Close()
            End If
        End If
    End Sub

    Sub Main()
        Console.Write("Initializing...")
        If Initialize("ros") Then
            Console.WriteLine("[OK]")
            Console.WriteLine("Dumping")
            Dump()
        Else
            Console.WriteLine("[FAIL]")
            Console.WriteLine("Please start game first!")
            Console.WriteLine("Press any key to exit...")
            Console.ReadKey()
            End
        End If
    End Sub

    Sub Dump()
        Do While True
            Dim gameObject As IntPtr = ReadMemory(Of IntPtr)(m_BaseAddress + Client)
            Dim m_pFirst As IntPtr = ReadMemory(Of IntPtr)(gameObject + &HE94)
            Dim m_UnkObjectCount As Integer = ReadMemory(Of Integer)(gameObject + &HE98)
            Dim m_ppObjects As IntPtr = ReadMemory(Of IntPtr)(gameObject + &HE9C)
            Dim m_pNext As IntPtr = ReadMemory(Of IntPtr)(m_ppObjects)
            Dim m_pEnd As IntPtr = ReadMemory(Of IntPtr)(m_ppObjects + &H4)

            If m_UnkObjectCount > 0 And m_UnkObjectCount < 500 Then

                For index = 0 To m_UnkObjectCount + 2
                    If m_pNext = m_pEnd Then
                        m_pNext = ReadMemory(Of IntPtr)(m_pNext)
                        Continue For
                    End If
                    Dim encryptedEntity As Int32 = ReadMemory(Of Int32)(m_pNext + &HC)
                    Dim entityDecryptKey As Int32 = ReadMemory(Of Int32)(ReadMemory(Of IntPtr)(m_pNext + &H10))
                    Dim pEntity As IntPtr = (encryptedEntity Xor entityDecryptKey)
                    If pEntity = IntPtr.Zero Then
                        m_pNext = ReadMemory(Of IntPtr)(m_pNext)
                        Continue For
                    End If
                    GetEntryList(pEntity)
                    m_pNext = ReadMemory(Of IntPtr)(m_pNext)
                Next
            End If
            Threading.Thread.Sleep(100)
        Loop

    End Sub

End Module

<StructLayout(LayoutKind.Sequential)>
Public Structure Vect2
    Private _X As Single
    Private _Y As Single
    Public Sub New(ByVal X As Single, ByVal Y As Single, ByVal Z As Single)
        _X = X
        _Y = Y
    End Sub

    Public Property X() As Single
        Get
            Return _X
        End Get
        Set(value As Single)
            _X = value
        End Set
    End Property

    Public Property Y() As Single
        Get
            Return _Y
        End Get
        Set(value As Single)
            _Y = value
        End Set
    End Property
End Structure

<StructLayout(LayoutKind.Sequential)>
Public Structure Vect3
    Private _X As Single
    Private _Y As Single
    Private _Z As Single
    Public Sub New(ByVal X As Single, ByVal Y As Single, ByVal Z As Single)
        _X = X
        _Y = Y
        _Z = Z
    End Sub

    Public Sub CopyTo(ByRef new_position As Vect3)
        new_position.X = _X
        new_position.Y = _Y
        new_position.Z = _Z
    End Sub

    Public Property X() As Single
        Get
            Return _X
        End Get
        Set(value As Single)
            _X = value
        End Set
    End Property

    Public Property Y() As Single
        Get
            Return _Y
        End Get
        Set(value As Single)
            _Y = value
        End Set
    End Property

    Public Property Z() As Single
        Get
            Return _Z
        End Get
        Set(value As Single)
            _Z = value
        End Set
    End Property

End Structure

<StructLayout(LayoutKind.Sequential)>
Public Structure Vect4
    Private _X As Single
    Private _Y As Single
    Private _Z As Single
    Private _W As Single
    Public Sub New(ByVal X As Single, ByVal Y As Single, ByVal Z As Single, ByVal W As Single)
        _X = X
        _Y = Y
        _Z = Z
        _W = W
    End Sub

    Public Property X() As Single
        Get
            Return _X
        End Get
        Set(value As Single)
            _X = value
        End Set
    End Property

    Public Property Y() As Single
        Get
            Return _Y
        End Get
        Set(value As Single)
            _Y = value
        End Set
    End Property

    Public Property Z() As Single
        Get
            Return _Z
        End Get
        Set(value As Single)
            _Z = value
        End Set
    End Property

    Public Property W() As Single
        Get
            Return _W
        End Get
        Set(value As Single)
            _W = value
        End Set
    End Property
End Structure
