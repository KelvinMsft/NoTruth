#pragma once	
#include <winioctl.h>
#define FILE_DEVICE_HIDE	0x8000

#define IOCTL_BASE	0x800

#define CTL_CODE_HIDE(i)	\
	CTL_CODE(FILE_DEVICE_HIDE, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_HIDE_ADD				CTL_CODE_HIDE(1)			//初始化
#define IOCTL_HIDE_START			CTL_CODE_HIDE(2)			//初始化
#define IOCTL_HIDE_STOP				CTL_CODE_HIDE(3)			//初始化