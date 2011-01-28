/*
 * linux-vmshm -- Guest driver for the VMShm PCI Device.
 *
 * Copyright (C) 2009-2010  The University of Napoli Parthenope at Naples.
 *
 * This file is part of linux-vmshm.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by: Giuseppe Coviello <giuseppe.coviello@uniparthenope.it>,
 *             Department of Applied Science
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <asm/system.h>
#include <asm/uaccess.h>

MODULE_DESCRIPTION("Guest driver for the VMShm PCI Device.");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Giuseppe Coviello <giuseppe.coviello@uniparthenope.it>");
MODULE_LICENSE("GPL");

#define VMSHM_ERR(fmt, args...) printk( KERN_ERR "vmshm: " fmt "\n", ## args)
#define VMSHM_INFO(fmt, args...) printk( KERN_INFO "vmshm: " fmt "\n", ## args)

#ifndef VMSHM_MAJOR
#define VMSHM_MAJOR 0
#endif

/* Registers */
/* Read Only */
#define VMSHM_OPEN_L_REG(dev)       ((dev)->regs)
#define VMSHM_CLOSE_L_REG(dev)      ((dev)->regs + 0x20)

struct vmshm_dev {
	struct pci_dev *pdev;

	void __iomem *regs;
	uint32_t regaddr;
	uint32_t reg_size;

	void *buffer;
	uint32_t size;
	uint32_t length;
	uint32_t addr;

	char *name;
	uint32_t name_size;
	uint32_t name_addr;

	struct semaphore sem;
	struct cdev cdev;

	wait_queue_head_t wait_queue;
	int wait_cond;
} vmshm_device;

static struct vmshm_dev vmshm_dev;
static atomic_t vmshm_available = ATOMIC_INIT(1);
static struct class *fc = NULL;
int vmshm_major = VMSHM_MAJOR;
int vmshm_minor = 0;

static int vmshm_open(struct inode *inode, struct file *filp)
{
	struct vmshm_dev *dev = &vmshm_dev;

	if (!atomic_dec_and_test(&vmshm_available)) {
		atomic_inc(&vmshm_available);
		return -EBUSY;
	}

	filp->private_data = dev;
	return 0;
}

static int vmshm_release(struct inode *inode, struct file *filp)
{
	struct vmshm_dev *dev = filp->private_data;
	int status = 0;

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	if ((status = readl(VMSHM_CLOSE_L_REG(&vmshm_dev))) != 0)
		VMSHM_ERR("can't close connection.");
	atomic_inc(&vmshm_available);
	up(&dev->sem);
	return status;
}

static int vmshm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long len;
	unsigned long off;
	unsigned long start;
	struct vmshm_dev *dev = filp->private_data;

	lock_kernel();

	off = vma->vm_pgoff << PAGE_SHIFT;
	start = dev->addr;

	len = PAGE_ALIGN((start & ~PAGE_MASK) + dev->size);
	start &= PAGE_MASK;

	if ((vma->vm_end - vma->vm_start + off) > len) {
		unlock_kernel();
		return -EINVAL;
	}

	off += start;
	vma->vm_pgoff = off >> PAGE_SHIFT;

	vma->vm_flags |= VM_SHARED | VM_RESERVED;

	if (io_remap_pfn_range(vma, vma->vm_start,
			       off >> PAGE_SHIFT, vma->vm_end - vma->vm_start,
			       vma->vm_page_prot)) {
		unlock_kernel();
		return -ENXIO;
	}

	unlock_kernel();

	return 0;
}

int vmshm_ioctl(struct inode *inode, struct file *filp,
		unsigned int ioctl_num, unsigned long ioctl_param)
{
	struct vmshm_dev *dev = filp->private_data;
	size_t size = 0;
	char *name = (char *)ioctl_param;
	for (size = 0; size < dev->name_size && name[size] != 0; size++)
		dev->name[size] = name[size];
	dev->name[size] = 0;

	if (readl(VMSHM_OPEN_L_REG(dev)) != 0)
		return -1;

	dev->addr = pci_resource_start(dev->pdev, 1);
	dev->buffer = pci_iomap(dev->pdev, 1, 0);
	dev->size = pci_resource_len(dev->pdev, 1);
	if (!dev->buffer) {
		VMSHM_ERR("cannot ioremap input buffer.");
		return -1;
	}

	VMSHM_INFO("buffer size: %d @ 0x%x.", dev->size, dev->addr);

	return 0;
}

static const struct file_operations vmshm_fops = {
	.owner = THIS_MODULE,
	.open = vmshm_open,
	.release = vmshm_release,
	.mmap = vmshm_mmap,
	.ioctl = vmshm_ioctl
};

static struct pci_device_id vmshm_id_table[] = {
	{0x1af4, 0x6661, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0},
};

MODULE_DEVICE_TABLE(pci, vmshm_id_table);

static int vmshm_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int result;

	result = pci_enable_device(pdev);

	if (result) {
		VMSHM_ERR("cannot probe device %s: error %d.",
			  pci_name(pdev), result);
		return result;
	}

	vmshm_dev.pdev = pdev;

	result = pci_request_regions(pdev, "vmshm");
	if (result < 0) {
		VMSHM_ERR("cannot request regions.");
		goto pci_disable;
	}

	/* Registers */
	vmshm_dev.regaddr = pci_resource_start(pdev, 0);
	vmshm_dev.reg_size = pci_resource_len(pdev, 0);
	vmshm_dev.regs = pci_iomap(pdev, 0, 0x100);
	if (!vmshm_dev.regs) {
		VMSHM_ERR("cannot ioremap registers.");
		goto reg_release;
	}

	/* I/O Buffers */
	vmshm_dev.addr = pci_resource_start(pdev, 1);
	vmshm_dev.buffer = pci_iomap(pdev, 1, 0);
	vmshm_dev.size = pci_resource_len(pdev, 1);
	vmshm_dev.length = 0;
	if (!vmshm_dev.buffer) {
		VMSHM_ERR("cannot ioremap input buffer.");
		goto in_release;
	}

	vmshm_dev.name_addr = pci_resource_start(pdev, 2);
	vmshm_dev.name = pci_iomap(pdev, 2, 0);
	vmshm_dev.name_size = pci_resource_len(pdev, 2);
	if (!vmshm_dev.name) {
		VMSHM_ERR("cannot ioremap name buffer.");
		goto name_release;
	}

	init_waitqueue_head(&vmshm_dev.wait_queue);
	init_MUTEX(&vmshm_dev.sem);
	cdev_init(&vmshm_dev.cdev, &vmshm_fops);
	vmshm_dev.cdev.owner = THIS_MODULE;
	vmshm_dev.cdev.ops = &vmshm_fops;
	result = cdev_add(&vmshm_dev.cdev, MKDEV(vmshm_major, vmshm_minor), 1);
	if (result)
		VMSHM_ERR("error %d adding vmshm%d", result, vmshm_minor);

	VMSHM_INFO("registered device, major: %d minor: %d.",
		   vmshm_major, vmshm_minor);
	VMSHM_INFO("buffer size: %d @ 0x%x.", vmshm_dev.size, vmshm_dev.addr);
	VMSHM_INFO("name size: %d @ 0x%x.",
		   vmshm_dev.name_size, vmshm_dev.name_addr);

	/* create sysfs entry */
	if (fc == NULL)
		fc = class_create(THIS_MODULE, "vmshm");
	device_create(fc, NULL, vmshm_dev.cdev.dev, NULL, "%s%d", "vmshm",
		      vmshm_minor);

	return 0;

name_release:
	pci_iounmap(pdev, vmshm_dev.buffer);
in_release:
	pci_iounmap(pdev, vmshm_dev.regs);
reg_release:
	pci_release_regions(pdev);
pci_disable:
	pci_disable_device(pdev);
	return -EBUSY;
}

static void vmshm_remove(struct pci_dev *pdev)
{
	VMSHM_INFO("unregistered device.");
	device_destroy(fc, vmshm_dev.cdev.dev);
	pci_iounmap(pdev, vmshm_dev.regs);
	pci_iounmap(pdev, vmshm_dev.buffer);
	pci_iounmap(pdev, vmshm_dev.name);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	if (fc != NULL) {
		class_destroy(fc);
		fc = NULL;
	}

}

static struct pci_driver vmshm_pci_driver = {
	.name = "vmshm",
	.id_table = vmshm_id_table,
	.probe = vmshm_probe,
	.remove = vmshm_remove,
};

static int __init vmshm_init_module(void)
{
	int result;
	dev_t dev = 0;

	if (vmshm_major) {
		dev = MKDEV(vmshm_major, vmshm_minor);
		result = register_chrdev_region(dev, 1, "vmshm");
	} else {
		result = alloc_chrdev_region(&dev, vmshm_minor, 1, "vmshm");
		vmshm_major = MAJOR(dev);
	}

	if (result < 0) {
		VMSHM_ERR("can't get major %d.", vmshm_major);
		return result;
	}

	if ((result = pci_register_driver(&vmshm_pci_driver)) != 0) {
		VMSHM_ERR("can't register PCI driver.");
		return result;
	}

	return 0;
}

module_init(vmshm_init_module);

static void __exit vmshm_exit(void)
{
	cdev_del(&vmshm_dev.cdev);
	pci_unregister_driver(&vmshm_pci_driver);
	unregister_chrdev_region(MKDEV(vmshm_major, vmshm_minor), 1);
}

module_exit(vmshm_exit);
