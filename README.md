# NoTruth
NoTruth is an Open Source light-weighted for hiding user-mode memory based on VT-x in Windows x64 platform. 

# Environment
- Visual Studio 2015 update 3 
- Windows SDK 10
- Windowr Driver Kit 10 
- VMware 12 with EPT environment. 
- Supports Multi-core processor environment
- Test environment with Windows 7 x64 sp1

# Description 
VT-x/EPT for User Memory Hiding hiding. Faking Any read memory read operation in the OS.
So that it could be used for bypassing any checksum in user mode memory. 

# Expected Output
 Let any one reading a faked value. But CPU execution
 As a reuslt should be expected as following :
 <img src= https://cloud.githubusercontent.com/assets/22551808/24321665/d6e3d6ba-118c-11e7-8585-ad40f80daf23.png></img>

 Explanation:
 - There is a test-case in VTxRing3 with a 20 number of threads, 10 for memory reading the memory, 10 for executing the function.
 1: Read correct value of that function.
 2: In case some on execute on that function, it throw exception, becoz we write a 0xCC on that.
 
# User Mode Test:  
NoTruth can be tested by user mode with Multi-Core Processor Configuration 
For Making a test case simple, we simply used x64dbg + notepad(x64) for demonstration.

Basically, we could use x64dbg to editing the text section of notepad as following and we could compare the result : 

<img src="https://cloud.githubusercontent.com/assets/22551808/24195359/61737e1c-0f34-11e7-92d6-2022db58695d.png" width="70%" height="70%"> </img>

<img src="https://cloud.githubusercontent.com/assets/22551808/24195372/6a76313a-0f34-11e7-8e0d-3832297f69b2.png" width="70%" height="70%"> </img>
 
Open a notepad.exe(x64) and VTxRing3.exe with administrator, by clicking on LoadDriver to loading NoTruth driver: 

<img src="https://cloud.githubusercontent.com/assets/22551808/24195373/6aa062d4-0f34-11e7-9819-c7bdbdbe8203.png" width="30%" height="30%"> </img>

After the NoTruth Driver is loaded, do the same things as previous(modifing memory), write a 0xCC on NtCreateFile : 

<img src="https://cloud.githubusercontent.com/assets/22551808/24195375/6ac79340-0f34-11e7-873f-a725b1e73e5c.png" width="70%" height="70%"> </img>


<img src="https://cloud.githubusercontent.com/assets/22551808/24195376/6ac79796-0f34-11e7-951e-de6758355933.png" width="70%" height="70%"> </img>

We could see, the memory hasn't changed as following from debugger aspect :
 
<img src="https://cloud.githubusercontent.com/assets/22551808/24195374/6ac552ce-0f34-11e7-810c-620ddce8873e.png" width="70%" height="70%"> </img>

 
We are going to execute once NtCreateFile by notepad.exe :

<img src="https://cloud.githubusercontent.com/assets/22551808/24195379/6acbaef8-0f34-11e7-961e-fcd40b613b5b.png" width="70%" height="70%"> </img>

 
It is breaked on that instruction,  but debugging can't realize it is 0xCC (breakpoint instruction) , then the exception comes

<img src="https://cloud.githubusercontent.com/assets/22551808/24195377/6ac7b4ce-0f34-11e7-91e3-b77f70557e23.png" width="70%" height="70%"> </img>

Finally, close the notepad.exe, release and unlock the memory.

<img src="https://cloud.githubusercontent.com/assets/22551808/24195378/6acb744c-0f34-11e7-9c21-f2af1914b7a7.png" width="70%" height="70%"> </img>

# TODO:
Debug... 

# Reference:
 https://github.com/tandasat/HyperPlatform
 
 
 
