#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.8.2)

project(demo_vm_virtio_net C)

find_package(os-sdk REQUIRED)
os_sdk_set_defaults()
set(LibUtilsDefaultZfLogLevel 2 CACHE STRING "")


# Kernel settings
set(KernelArmHypervisorSupport ON CACHE BOOL "" FORCE)
set(KernelArmVtimerUpdateVOffset OFF CACHE BOOL "" FORCE)
set(KernelArmDisableWFIWFETraps ON CACHE BOOL "" FORCE)
set(LibUSB OFF CACHE BOOL "" FORCE)
set(VmInitRdFile ON CACHE BOOL "" FORCE)
#set(VmVirtioConsole ON CACHE BOOL "" FORCE)
set(CapDLLoaderMaxObjects 8192 CACHE STRING "" FORCE)
set(VmVirtioNetVirtqueue ON CACHE BOOL "" FORCE)
set(VmPCISupport ON CACHE BOOL "" FORCE)

include("${CMAKE_CURRENT_LIST_DIR}/plat/${PLATFORM}/plat.cmake")

os_sdk_setup()
CAmkESAddCPPInclude("plat/${PLATFORM}")

#-------------------------------------------------------------------------------
# cherry pick global components

CAmkESAddImportPath("${SDK_SEL4_CAMKES_GLOBAL_COMPS_DIR}/components")

foreach(
    comp IN ITEMS
    FileServer
    VirtQueue
)
    add_subdirectory(
        "${SDK_SEL4_CAMKES_GLOBAL_COMPS_DIR}/components/${comp}"
        global_components/${comp}
    )
endforeach()

#-------------------------------------------------------------------------------
# config
AddCamkesCPPFlag(cpp_flags CONFIG_VARS VmEmmc2NoDMA)

if(NOT KernelPlatformQEMUArmVirt)
    AddCamkesCPPFlag(cpp_flags CONFIG_VARS VmVUSB)
endif()

if(KernelPlatformTK1)
    AddCamkesCPPFlag(cpp_flags CONFIG_VARS Tk1DeviceFwd Tk1Insecure)
endif()


#-------------------------------------------------------------------------------
# File server

list(
    APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_LIST_DIR}/camkes-vm-images"
    "${CMAKE_CURRENT_LIST_DIR}/camkes-vm-linux"
)
find_package(camkes-vm-images REQUIRED)
find_package(camkes-vm-linux REQUIRED)

include("${CAMKES_VM_LINUX_HELPERS_PATH}")

AddToFileServer("linux" "${CAMKES_VM_IMAGES_DIR}/${PLATFORM}/linux")
set(VM_ROOTFS_FILE "${CAMKES_VM_IMAGES_DIR}/${PLATFORM}/rootfs.cpio.gz")

# Generate overlayed rootfs
AddFileToOverlayDir(
    "interfaces"
    ${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/network_interfaces/interfaces
    "etc/network"
    overlay
)
AddFileToOverlayDir(
    "S90ping_test"
    ${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/init_scripts/ping_test
    "etc/init.d"
    overlay
)

AddOverlayDirToRootfs(
    overlay
    ${VM_ROOTFS_FILE}
    "buildroot"
    "rootfs_install"
    VM_ROOTFS_FILE_PATCHED
    rootfs_target
    GZIP
)

DefineCAmkESVMFileServer(
    INSTANCE "fileServer"
    FILES
        "linux:${VM_IMG_LINUX}"
        "linux-initrd:${VM_IMG_ROOTFS_PATCHED}"
        "linux-dtb:${VM_IMG_DTB_PATCHED}"
    DEPENDS
        rootfs_target 
        target_dtb_gen
)

ExtendCAmkESComponentInstance(
    FileServer
    fileServer
    LIBS
        fileserver_cpio
)


CAmkESAddCPPInclude("${SDK_SEL4_CAMKES_DIR}/libs/sel4_projects_libs/libsel4vm/include/sel4vm")

DeclareCAmkESComponent(
    PingClient
    INCLUDES
    	# no include paths needed
    SOURCES
    	components/PingClient/ping_client.c
    C_FLAGS
    	-Wall
	-Werror
    LIBS
    	virtqueue
    	sel4_autoconf
    )

os_sdk_create_CAmkES_system("vm_echo_ping.camkes")
