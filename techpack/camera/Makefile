# Makefile for use with Android's kernel/build system

KBUILD_OPTIONS += CAMERA_KERNEL_ROOT=$(srctree)/techpack/camera
KBUILD_OPTIONS += KERNEL_ROOT=$(srctree)
KBUILD_OPTIONS += MODNAME=camera
KBUILD_OPTIONS += MODNAME=cameralog
all: modules

modules dtbs:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS)

modules_install:
	$(MAKE) M=$(M) -C $(KERNEL_SRC) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) clean
