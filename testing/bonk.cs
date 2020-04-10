using System;
using System.Management;
using System.Security;
using System.Net.NetworkInformation;

namespace HelloWorld
{
class Hello 
{
static void Main() 
{
ManagementObject os = new ManagementObject("Win32_OperatingSystem=@");
string osGuid = (string)os["SerialNumber"];
string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
// ------- ------- ------- ------- -------
Console.WriteLine("Machine GUID: {0}",osGuid);
Console.WriteLine("User Name: {0}",userName);
// ------- ------- ------- ------- -------
ManagementObjectSearcher mos1 = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
foreach(ManagementObject proc in mos1.Get())
{
Console.WriteLine("Process: {0} / {1}",proc["Name"],proc["CommandLine"]);
}
// ------- ------- ------- ------- -------
ManagementObjectSearcher mos2 = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
foreach (ManagementObject WniHD in mos2.Get())
{
try{
Console.WriteLine("Drive: {0} {1} {2} {3}",WniHD["Model"].ToString(),WniHD["InterfaceType"].ToString(),WniHD["MediaType"].ToString(),Convert.ToUInt64(WniHD["Size"]));
}
catch(Exception)
{
}
}
// ------- ------- ------- ------- -------
ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT * FROM Win32_Product");
foreach(ManagementObject mo in mos.Get())
{
Console.WriteLine("Installed: {0}",mo["Name"]);
}
// ------- ------- ------- ------- -------
foreach(NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
{
Console.WriteLine("MAC: {0}",nic.GetPhysicalAddress().ToString());
}

Console.WriteLine("Press any key to exit.");
Console.ReadKey();
}
}
}