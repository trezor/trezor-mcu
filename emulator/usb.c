/*
 * Copyright (C) 2018 Yannick Heneault <yheneaul@gmail.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/sysmacros.h>

#if defined(TRANSPORT_USBG)
#include <usbg/usbg.h>
#include <usbg/function/hid.h>
#endif

#include <libopencm3/usb/usbd.h>

#include "emulator.h"

#define MAX_INTERFACE 4

enum _usbd_transaction {
	USB_TRANSACTION_IN,
	USB_TRANSACTION_OUT
};

struct _usbd_driver {
};

struct _usbd_endpoint {
	int fd;
	usbd_endpoint_callback callback;
};

struct _report_descriptor {
	uint8_t *data;
	uint16_t length;
};

struct _usbd_device {
	const struct usb_config_descriptor *config_descriptor;
	const struct usb_device_descriptor *device_descriptor;
	const char **strings;
	int num_strings;

	struct _usbd_endpoint ep[MAX_INTERFACE][2];

	struct _report_descriptor report_descriptor[MAX_INTERFACE];
};

const struct _usbd_driver otgfs_usb_driver = { };

const char *get_string(usbd_device * usbd_dev, int index) {
	if (index < 0 || index >= usbd_dev->num_strings) {
		fprintf(stderr, "invalid string index : %d\n", index);
		exit(1);
	}
	return usbd_dev->strings[index];
}

usbd_device *usbd_init(const usbd_driver * driver,
		       const struct usb_device_descriptor * device_descriptor,
		       const struct usb_config_descriptor * config_descriptor,
		       const char **strings, int num_strings,
		       uint8_t * control_buffer, uint16_t control_buffer_size) {
	(void) driver;
	(void) control_buffer;
	(void) control_buffer_size;

	struct _usbd_device *device = calloc(sizeof(struct _usbd_device), 1);

	device->device_descriptor = device_descriptor;
	device->config_descriptor = config_descriptor;
	device->strings = strings;
	device->num_strings = num_strings;

	for (int i = 0; i < MAX_INTERFACE; i++) {
		device->ep[i][USB_TRANSACTION_IN].fd = device->ep[i][USB_TRANSACTION_OUT].fd = -1;
	}
	return device;
}

uint16_t usbd_ep_read_packet(usbd_device * usbd_dev, uint8_t addr, void *buf, uint16_t len) {
	return read(usbd_dev->ep[addr][USB_TRANSACTION_OUT].fd, buf, len);
}

void usbd_poll(usbd_device * usbd_dev) {
	emulatorPoll();

	for (int i = 1; i < MAX_INTERFACE; i++) {
		int fd = usbd_dev->ep[i][USB_TRANSACTION_OUT].fd;

		if (fd != -1) {
			struct pollfd pollfd;

			pollfd.fd = fd;
			pollfd.events = POLLIN;

			int ret = poll(&pollfd, 1, 1);

			if (ret == 1) {
				usbd_dev->ep[i][USB_TRANSACTION_OUT].callback(usbd_dev, i);
				return;
			}
		}
	}
}

uint16_t usbd_ep_write_packet(usbd_device * usbd_dev, uint8_t addr, const void *buf, uint16_t len) {
	addr &= 0x7f;
	return write(usbd_dev->ep[addr][USB_TRANSACTION_IN].fd, buf, len);
}

void usbd_ep_setup(usbd_device * usbd_dev, uint8_t addr, uint8_t type,
		   uint16_t max_size, usbd_endpoint_callback callback) {
	(void) type;
	(void) max_size;

	enum _usbd_transaction dir = addr & 0x80 ? USB_TRANSACTION_IN : USB_TRANSACTION_OUT;
	addr &= 0x7f;

	if (addr >= MAX_INTERFACE) {
		fprintf(stderr, "invalid ep address : %d\n", addr);
		exit(1);
	}

	if (callback) {
		usbd_dev->ep[addr][dir].callback = (void *) callback;
	}
}

int usbd_register_control_callback(usbd_device * usbd_dev, uint8_t type,
				   uint8_t type_mask, usbd_control_callback callback) {
	(void) type;
	(void) type_mask;

	for (int i = 0; i < usbd_dev->config_descriptor->bNumInterfaces; i++) {
		struct usb_setup_data req = { 0 };
		req.bmRequestType = 0x81;
		req.bRequest = USB_REQ_GET_DESCRIPTOR;
		req.wValue = 0x2200;
		req.wIndex = i;
		req.wLength = 0;

		(*callback) (usbd_dev, &req,
			     &usbd_dev->report_descriptor[i].data,
			     &usbd_dev->report_descriptor[i].length, NULL);
	}
	return 0;
}

#if defined(TRANSPORT_USBG)
int usbd_register_set_config_callback(usbd_device * usbd_dev, usbd_set_config_callback callback) {
	usbg_state *usbg_state;

	int usbg_ret;

	usbg_ret = usbg_init("/sys/kernel/config", &usbg_state);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on usbg init: %s : %s\n",
			usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
		exit(1);
	}
	//remove the current instance if any
	usbg_gadget *old_gadget = usbg_get_gadget(usbg_state, "trezor");

	if (old_gadget != NULL) {
		usbg_ret = usbg_rm_gadget(old_gadget, USBG_RM_RECURSE);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error removing gadget: %s : %s\n",
				usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
			exit(1);
		}
	}

	struct usbg_gadget_attrs g_attrs = { 0 };
	g_attrs.bcdUSB = usbd_dev->device_descriptor->bcdUSB;
	g_attrs.bDeviceClass = usbd_dev->device_descriptor->bDeviceClass;
	g_attrs.bDeviceSubClass = usbd_dev->device_descriptor->bDeviceSubClass;
	g_attrs.bDeviceProtocol = usbd_dev->device_descriptor->bDeviceProtocol;
	g_attrs.bMaxPacketSize0 = usbd_dev->device_descriptor->bMaxPacketSize0;
	g_attrs.idVendor = usbd_dev->device_descriptor->idVendor;
	g_attrs.idProduct = usbd_dev->device_descriptor->idProduct;
	g_attrs.bcdDevice = usbd_dev->device_descriptor->bcdDevice;

	struct usbg_gadget_strs g_strs = { 0 };
	g_strs.manufacturer = (char *) get_string(usbd_dev, USBG_STR_MANUFACTURER);
	g_strs.product = (char *) get_string(usbd_dev, USBG_STR_PRODUCT);
	g_strs.serial = (char *) get_string(usbd_dev, USBG_STR_SERIAL_NUMBER);

	usbg_gadget *usbg_gadget;

	usbg_ret = usbg_create_gadget(usbg_state, "trezor", &g_attrs, &g_strs, &usbg_gadget);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error creating gadget: %s : %s\n",
			usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
		exit(1);
	}

	struct usbg_config_attrs c_attrs;

	c_attrs.bmAttributes = usbd_dev->config_descriptor->bmAttributes;
	c_attrs.bMaxPower = usbd_dev->config_descriptor->bMaxPower;

	usbg_config *usbg_config;

	usbg_ret = usbg_create_config(usbg_gadget, 1, NULL, &c_attrs, NULL, &usbg_config);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error creating config: %s : %s\n",
			usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
		exit(1);
	}

	(*callback) (usbd_dev, usbd_dev->config_descriptor->bConfigurationValue);

	usbg_function *usbg_f_hid[MAX_INTERFACE];

	if (usbd_dev->config_descriptor->bNumInterfaces >= MAX_INTERFACE) {
		fprintf(stderr, "Invalid number of interfaces\n");
		exit(1);
	}

	for (int i = 0; i < usbd_dev->config_descriptor->bNumInterfaces; i++) {
		struct usbg_f_hid_attrs f_attrs = { 0 };

		const struct usb_interface_descriptor *intf =
			usbd_dev->config_descriptor->interface[i].altsetting;

		f_attrs.protocol = intf->bInterfaceProtocol;
		f_attrs.report_desc.desc = (char *) usbd_dev->report_descriptor[i].data;
		f_attrs.report_desc.len = usbd_dev->report_descriptor[i].length;
		f_attrs.report_length = intf->endpoint[0].wMaxPacketSize;
		f_attrs.subclass = intf->bInterfaceSubClass;

		usbg_ret =
			usbg_create_function(usbg_gadget, USBG_F_HID,
					     get_string(usbd_dev,
							intf->iInterface - 1),
					     &f_attrs, &usbg_f_hid[i]);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error creating function: %s : %s\n",
				usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
			exit(1);
		}

		usbg_ret =
			usbg_add_config_function(usbg_config,
						 get_string(usbd_dev,
							    intf->iInterface - 1), usbg_f_hid[i]);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error adding function: %s : %s\n",
				usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
			exit(1);
		}
	}

	usbg_ret = usbg_enable_gadget(usbg_gadget, DEFAULT_UDC);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error enabling gadget: %s : %s\n",
			usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
		exit(1);
	}

	for (int i = 0; i < usbd_dev->config_descriptor->bNumInterfaces; i++) {
		dev_t dev;

		usbg_ret = usbg_f_hid_get_dev(usbg_to_hid_function(usbg_f_hid[i]), &dev);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error getting dev: %s : %s\n",
				usbg_error_name(usbg_ret), usbg_strerror(usbg_ret));
			exit(1);
		}
		char dev_filename[20];

		sprintf(dev_filename, "/dev/hidg%d", minor(dev));
		int fd = open(dev_filename, O_RDWR | O_NONBLOCK);

		if (fd == -1) {
			fprintf(stderr, "Error opening hidg device: %s\n", dev_filename);
			exit(1);
		}
		const struct usb_interface_descriptor *intf =
			usbd_dev->config_descriptor->interface[i].altsetting;

		for (int j = 0; j < intf->bNumEndpoints; j++) {
			uint8_t addr = intf->endpoint[j].bEndpointAddress;

			addr &= 0x7f;
			usbd_dev->ep[addr][USB_TRANSACTION_IN].fd =
				usbd_dev->ep[addr][USB_TRANSACTION_OUT].fd = fd;
		}
	}
	return 0;
}
#endif

#if defined(TRANSPORT_PIPE)

int usbd_register_set_config_callback(usbd_device * usbd_dev, usbd_set_config_callback callback) {
	(*callback) (usbd_dev, usbd_dev->config_descriptor->bConfigurationValue);

	if (usbd_dev->config_descriptor->bNumInterfaces >= MAX_INTERFACE) {
		fprintf(stderr, "Invalid number of interfaces\n");
		exit(1);
	}

	for (int i = 0; i < usbd_dev->config_descriptor->bNumInterfaces; i++) {
		const struct usb_interface_descriptor *intf =
			usbd_dev->config_descriptor->interface[i].altsetting;
		char *prefix;

		switch (intf->iInterface) {
			case 4:
				prefix = "/tmp/pipe.trezor";
				break;
			case 5:
				prefix = "/tmp/pipe.trezor_debug";
				break;
			case 6:
				continue;	//skip u2f interface
			default:
				fprintf(stderr, "unknown usb interface\n");
				exit(1);
		}

		for (int j = 0; j < intf->bNumEndpoints; j++) {
			uint8_t addr = intf->endpoint[j].bEndpointAddress;
			enum _usbd_transaction dir =
				addr & 0x80 ? USB_TRANSACTION_IN : USB_TRANSACTION_OUT;

			const char *dir_name = dir == USB_TRANSACTION_IN ? ".from" : ".to";

			addr &= 0x7f;
			char filename[255] = { 0 };
			strcpy(filename, prefix);
			strcat(filename, dir_name);
			mkfifo(filename, 0600);
			int fd = open(filename, O_RDWR | O_NONBLOCK);

			if (fd == -1) {
				fprintf(stderr, "Error opening pipe device: %s\n", filename);
				exit(1);
			}

			usbd_dev->ep[addr][dir].fd = fd;
		}
	}
	return 0;
}

#endif

void usbd_disconnect(usbd_device * usbd_dev, bool disconnected) {
	(void) usbd_dev;
	(void) disconnected;
	//not supported
}
