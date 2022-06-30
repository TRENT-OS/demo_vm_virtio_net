#
# Copyright (C) 2022-2023, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.8.2)

project(demo_vm_virtio_net C)

#-------------------------------------------------------------------------------
# use the SDK
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

include("plat/${PLATFORM}/plat.cmake")

os_sdk_setup()
os_sdk_import_camkes_vm()
os_sdk_import_from_global_components(
    "components/FileServer"
    "components/VirtQueue"
)

CAmkESAddCPPInclude("plat/${PLATFORM}")


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
# VM Images

list(
    APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_LIST_DIR}/camkes-vm-images"
    "${CMAKE_CURRENT_LIST_DIR}/camkes-vm-linux"
)
find_package(camkes-vm-images REQUIRED)
find_package(camkes-vm-linux REQUIRED)
include("${CAMKES_VM_LINUX_HELPERS_PATH}")

# images for the selected platform
set(VM_IMG_LINUX "${CAMKES_VM_IMAGES_DIR}/${PLATFORM}/linux")
set(VM_IMG_ROOTFS "${CAMKES_VM_IMAGES_DIR}/${PLATFORM}/rootfs.cpio.gz")
set(VM_IMG_DTB "${CAMKES_VM_IMAGES_DIR}/${PLATFORM}/linux-dtb")


# patch root-fs
AddOverlayDirToRootfs(
    overlay
    "${CAMKES_VM_IMAGES_DIR}/qemu-arm-virt/rootfs.cpio.gz"
    "buildroot"
    "rootfs_install"
    VM_IMG_ROOTFS_PATCHED
    rootfs_target
    GZIP
)
AddFileToOverlayDir(
    "interfaces"
    "${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/network_interfaces/interfaces"
    "etc/network"
    overlay
)
AddFileToOverlayDir(
    "S90ping_test"
    "${CMAKE_CURRENT_SOURCE_DIR}/overlay_files/init_scripts/ping_test"
    "etc/init.d"
    overlay
)

# patch DTB for use proper 'initrd-start' and 'initrd-end'
UpdateDtbFromInitrd(
    "${VM_IMG_DTB}"
    "${VM_IMG_ROOTFS_PATCHED}"
    "0x4d700000" # initrd start
    target_dtb_gen
    VM_IMG_DTB_PATCHED
)

# ToDo: make these parameters work to allow customization:
#
#           DefineCAmkESVMFileServer(
#               INSTANCE "fileServer"
#               FILES
#                   "linux:${VM_IMG_LINUX}"
#                   "linux-initrd:${VM_IMG_ROOTFS_PATCHED}"
#                   "linux-dtb:${VM_IMG_DTB_PATCHED}"
#               DEPENDS
#                   rootfs_target
#                   target_dtb_gen
#           )
#
# Until then we need to do it manually
AddToFileServer("linux" "${VM_IMG_LINUX}")
AddToFileServer("linux-initrd" "${VM_IMG_ROOTFS_PATCHED}" DEPENDS rootfs_target)
AddToFileServer("linux-dtb" "${VM_IMG_DTB_PATCHED}" DEPENDS target_dtb_gen)
get_target_property(FS_FILES vm_fserver_config FILES)
get_target_property(FS_DEPS   vm_fserver_config DEPS)
include(cpio)
MakeCPIO("file_server_archive.o" "${FS_FILES}" DEPENDS "${FS_DEPS}")
add_library(fileserver_cpio STATIC EXCLUDE_FROM_ALL "file_server_archive.o")
set_property(TARGET fileserver_cpio PROPERTY LINKER_LANGUAGE C)
ExtendCAmkESComponentInstance(FileServer fileServer LIBS fileserver_cpio)


#-------------------------------------------------------------------------------
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


#-------------------------------------------------------------------------------
os_sdk_create_CAmkES_system("vm_virtio_net.camkes")
