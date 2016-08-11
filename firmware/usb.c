/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/hid.h>

#include "trezor.h"
#include "usb.h"
#include "debug.h"
#include "messages.h"
#include "u2f.h"
#include "ccid.h"
#include "storage.h"
#include "util.h"
#include "timer.h"

#define USB_INTERFACE_INDEX_MAIN 0
#if DEBUG_LINK
#define USB_INTERFACE_INDEX_DEBUG 1
#define USB_INTERFACE_INDEX_U2F 2
#define USB_INTERFACE_INDEX_CCID 3
#else
#define USB_INTERFACE_INDEX_U2F 1
#define USB_INTERFACE_INDEX_CCID 2
#endif

#define ENDPOINT_ADDRESS_IN         (0x81)
#define ENDPOINT_ADDRESS_OUT        (0x01)
#define ENDPOINT_ADDRESS_U2F_IN     (0x82)
#define ENDPOINT_ADDRESS_U2F_OUT    (0x02)
#if DEBUG_LINK
#define ENDPOINT_ADDRESS_DEBUG_IN   (0x83)
#define ENDPOINT_ADDRESS_DEBUG_OUT  (0x03)
// TODO: invalid endpoint, provide mechanism to cope with lack of endpoints
#define ENDPOINT_ADDRESS_CCID_IN    (0x84)
#define ENDPOINT_ADDRESS_CCID_OUT   (0x04)
#else
#define ENDPOINT_ADDRESS_CCID_IN    (0x83)
#define ENDPOINT_ADDRESS_CCID_OUT   (0x03)
#endif

static const struct usb_device_descriptor dev_descr = {
	.bLength = USB_DT_DEVICE_SIZE,
	.bDescriptorType = USB_DT_DEVICE,
	.bcdUSB = 0x0200,
	.bDeviceClass = 0,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.bMaxPacketSize0 = 64,
	.idVendor = 0x534c,
	.idProduct = 0x0001,
	.bcdDevice = 0x0100,
	.iManufacturer = 1,
	.iProduct = 2,
	.iSerialNumber = 3,
	.bNumConfigurations = 1,
};

static const uint8_t hid_report_descriptor[] = {
	0x06, 0x00, 0xff,  // USAGE_PAGE (Vendor Defined)
	0x09, 0x01,        // USAGE (1)
	0xa1, 0x01,        // COLLECTION (Application)
	0x09, 0x20,        // USAGE (Input Report Data)
	0x15, 0x00,        // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
	0x75, 0x08,        // REPORT_SIZE (8)
	0x95, 0x40,        // REPORT_COUNT (64)
	0x81, 0x02,        // INPUT (Data,Var,Abs)
	0x09, 0x21,        // USAGE (Output Report Data)
	0x15, 0x00,        // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
	0x75, 0x08,        // REPORT_SIZE (8)
	0x95, 0x40,        // REPORT_COUNT (64)
	0x91, 0x02,        // OUTPUT (Data,Var,Abs)
	0xc0               // END_COLLECTION
};

static const uint8_t hid_report_descriptor_debug[] = {
	0x06, 0x01, 0xff,  // USAGE_PAGE (Vendor Defined)
	0x09, 0x01,        // USAGE (1)
	0xa1, 0x01,        // COLLECTION (Application)
	0x09, 0x20,        // USAGE (Input Report Data)
	0x15, 0x00,        // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
	0x75, 0x08,        // REPORT_SIZE (8)
	0x95, 0x40,        // REPORT_COUNT (64)
	0x81, 0x02,        // INPUT (Data,Var,Abs)
	0x09, 0x21,        // USAGE (Output Report Data)
	0x15, 0x00,        // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,  // LOGICAL_MAXIMUM (255)
	0x75, 0x08,        // REPORT_SIZE (8)
	0x95, 0x40,        // REPORT_COUNT (64)
	0x91, 0x02,        // OUTPUT (Data,Var,Abs)
	0xc0               // END_COLLECTION
};

static const uint8_t hid_report_descriptor_u2f[] = {
	0x06, 0xd0, 0xf1,  // USAGE_PAGE (FIDO Alliance)
	0x09, 0x01,        // USAGE (U2F HID Authenticator Device)
	0xa1, 0x01,        // COLLECTION (Application)
	0x09, 0x20,        // USAGE (Input Report Data)
	0x15, 0x00,        // LOGICAL_MINIMUM (0)
	0x26,0xff, 0x00,   // LOGICAL_MAXIMUM (255)
	0x75,0x08,         // REPORT_SIZE (8)
	0x95,0x40,         // REPORT_COUNT (64)
	0x81,0x02,         // INPUT (Data,Var,Abs)
	0x09,0x21,         // USAGE (Output Report Data)
	0x15,0x00,         // LOGICAL_MINIMUM (0)
	0x26,0xff, 0x00,   // LOGICAL_MAXIMUM (255)
	0x75,0x08,         // REPORT_SIZE (8)
	0x95,0x40,         // REPORT_COUNT (64)
	0x91,0x02,         // OUTPUT (Data,Var,Abs)
	0xc0               // END_COLLECTION
};

static const struct {
	struct usb_hid_descriptor hid_descriptor;
	struct {
		uint8_t bReportDescriptorType;
		uint16_t wDescriptorLength;
	} __attribute__((packed)) hid_report;
} __attribute__((packed)) hid_function = {
	.hid_descriptor = {
		.bLength = sizeof(hid_function),
		.bDescriptorType = USB_DT_HID,
		.bcdHID = 0x0111,
		.bCountryCode = 0,
		.bNumDescriptors = 1,
	},
	.hid_report = {
		.bReportDescriptorType = USB_DT_REPORT,
		.wDescriptorLength = sizeof(hid_report_descriptor),
	}
};

static const struct {
	struct usb_hid_descriptor hid_descriptor_u2f;
	struct {
		uint8_t bReportDescriptorType;
		uint16_t wDescriptorLength;
	} __attribute__((packed)) hid_report_u2f;
} __attribute__((packed)) hid_function_u2f = {
	.hid_descriptor_u2f = {
		.bLength = sizeof(hid_function_u2f),
		.bDescriptorType = USB_DT_HID,
		.bcdHID = 0x0111,
		.bCountryCode = 0,
		.bNumDescriptors = 1,
	},
	.hid_report_u2f = {
		.bReportDescriptorType = USB_DT_REPORT,
		.wDescriptorLength = sizeof(hid_report_descriptor_u2f),
	}
};

static const struct usb_ccid_descriptor ccid_descriptor = {
	.bLength = sizeof(ccid_descriptor),
	.bDescriptorType = USB_DT_HID,
	.bcdCCID = 0x0110,
	.bMaxSlotIndex = 0,
	.bVoltageSupport = 0x2,
	.dwProtocols = 0x02,
	.dwDefaultClock = 3580,
	.dwMaximumClock = 3580,
	.bNumClockSupported = 0,
	.dwDataRate = 9600,
	.dwMaxDataRate = 9600,
	.bNumDataRatesSupported = 0,
	.dwMaxIFSD = 0xFE,
	.dwSynchProtocols = 0,
	.dwMechanical = 0,
	.dwFeatures = 0x00020000 | 0x00000040 | 0x00000020 | 0x00000010 | 0x00000008 | 0x00000004 | 0x00000002,
	.dwMaxCCIDMessageLength = 0x10F,
	.bClassGetResponse = 0xFF,
	.bClassEnvelope = 0xFF,
	.wLcdLayout = 0,
	.bPINSupport = 0,
	.bMaxCCIDBusySlots = 1
};


static const struct usb_endpoint_descriptor hid_endpoints[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 1,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 1,
}};

static const struct usb_interface_descriptor hid_iface[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_MAIN,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = 0,
	.endpoint = hid_endpoints,
	.extra = &hid_function,
	.extralen = sizeof(hid_function),
}};

static const struct usb_endpoint_descriptor hid_endpoints_u2f[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_U2F_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 2,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_U2F_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 2,
}};

static const struct usb_interface_descriptor hid_iface_u2f[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_U2F,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = 0,
	.endpoint = hid_endpoints_u2f,
	.extra = &hid_function_u2f,
	.extralen = sizeof(hid_function_u2f),
}};

static const struct usb_endpoint_descriptor ccid_endpoints[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_CCID_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_BULK,
	.wMaxPacketSize = 64,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_CCID_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_BULK,
	.wMaxPacketSize = 64,
}};

static const struct usb_interface_descriptor ccid_iface[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_CCID,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_CSCID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = 0,
	.endpoint = ccid_endpoints,
	.extra = &ccid_descriptor,
	.extralen = sizeof(ccid_descriptor),
}};
#if DEBUG_LINK
static const struct usb_endpoint_descriptor hid_endpoints_debug[2] = {{
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_IN,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 1,
}, {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = ENDPOINT_ADDRESS_DEBUG_OUT,
	.bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
	.wMaxPacketSize = 64,
	.bInterval = 1,
}};

static const struct usb_interface_descriptor hid_iface_debug[] = {{
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = USB_INTERFACE_INDEX_DEBUG,
	.bAlternateSetting = 0,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_HID,
	.bInterfaceSubClass = 0,
	.bInterfaceProtocol = 0,
	.iInterface = 0,
	.endpoint = hid_endpoints_debug,
	.extra = &hid_function,
	.extralen = sizeof(hid_function),
}};
#endif

static const struct usb_interface ifaces[] = {{
	.num_altsetting = 1,
	.altsetting = hid_iface,
#if DEBUG_LINK
}, {
	.num_altsetting = 1,
	.altsetting = hid_iface_debug,
#endif
}, {
    .num_altsetting = 1,
    .altsetting = hid_iface_u2f,
}, {
	.num_altsetting = 1,
	.altsetting = ccid_iface,
}};

static const struct usb_config_descriptor config = {
	.bLength = USB_DT_CONFIGURATION_SIZE,
	.bDescriptorType = USB_DT_CONFIGURATION,
	.wTotalLength = 0,
#if DEBUG_LINK
	.bNumInterfaces = 4,
#else
	.bNumInterfaces = 3,
#endif
	.bConfigurationValue = 1,
	.iConfiguration = 0,
	.bmAttributes = 0x80,
	.bMaxPower = 0x32,
	.interface = ifaces,
};

static const char *usb_strings[] = {
	"SatoshiLabs",
	"TREZOR",
	(const char *)storage_uuid_str,
};

static int hid_control_request(usbd_device *dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len, usbd_control_complete_callback *complete)
{
	(void)complete;
	(void)dev;

	if ((req->bmRequestType != 0x81) ||
	    (req->bRequest != USB_REQ_GET_DESCRIPTOR) ||
	    (req->wValue != 0x2200))
		return 0;

	if (req->wIndex == USB_INTERFACE_INDEX_U2F) {
		debugLog(0, "", "hid_control_request u2f");
		*buf = (uint8_t *)hid_report_descriptor_u2f;
		*len = sizeof(hid_report_descriptor_u2f);
		return 1;
	}

#if DEBUG_LINK
	if (req->wIndex == USB_INTERFACE_INDEX_DEBUG) {
		debugLog(0, "", "hid_control_request debug");
		*buf = (uint8_t *)hid_report_descriptor_debug;
		*len = sizeof(hid_report_descriptor_debug);
		return 1;
	}
#endif

	debugLog(0, "", "hid_control_request main");
	*buf = (uint8_t *)hid_report_descriptor;
	*len = sizeof(hid_report_descriptor);
	return 1;
}

static volatile char tiny = 0;

static void hid_rx_callback(usbd_device *dev, uint8_t ep)
{
	(void)ep;
	static uint8_t buf[64] __attribute__ ((aligned(4)));
	if ( usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_OUT, buf, 64) != 64) return;
	debugLog(0, "", "hid_rx_callback");
	if (!tiny) {
		msg_read(buf, 64);
	} else {
		msg_read_tiny(buf, 64);
	}
}

static void hid_u2f_rx_callback(usbd_device *dev, uint8_t ep)
{
	(void)ep;
	static uint8_t buf[64] __attribute__ ((aligned(4)));

	debugLog(0, "", "hid_u2f_rx_callback");
    if ( usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_U2F_OUT, buf, 64) != 64) return;
	u2fhid_read(tiny, (const U2FHID_FRAME *) (void*) buf);
}

static void ccid_rx_callback(usbd_device *dev, uint8_t ep)
{
	(void)ep;
	// Extra byte needed for null termination when using string manipulation
	static uint8_t buf[65] __attribute__ ((aligned(4)));
	static struct ccid_header *header = (struct ccid_header *) buf;

	uint16_t size = usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_CCID_OUT, buf, sizeof(buf) - 1);
	if (size != sizeof(*header) + header->dwLength) return;
	ccid_read(header, buf + sizeof(*header));
}

#if DEBUG_LINK
static void hid_debug_rx_callback(usbd_device *dev, uint8_t ep)
{
	(void)ep;
	static uint8_t buf[64] __attribute__ ((aligned(4)));
	if ( usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_DEBUG_OUT, buf, 64) != 64) return;
	debugLog(0, "", "hid_debug_rx_callback");
	if (!tiny) {
		msg_debug_read(buf, 64);
	} else {
		msg_read_tiny(buf, 64);
	}
}
#endif

static void usb_set_config(usbd_device *dev, uint16_t wValue)
{
	(void)wValue;

	usbd_ep_setup(dev, ENDPOINT_ADDRESS_IN,  USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64, hid_rx_callback);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_IN,  USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_U2F_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64, hid_u2f_rx_callback);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_CCID_IN,  USB_ENDPOINT_ATTR_BULK, 64, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_CCID_OUT, USB_ENDPOINT_ATTR_BULK, 64, ccid_rx_callback);
#if DEBUG_LINK
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_IN,  USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
	usbd_ep_setup(dev, ENDPOINT_ADDRESS_DEBUG_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64, hid_debug_rx_callback);
#endif

	usbd_register_control_callback(
		dev,
		USB_REQ_TYPE_STANDARD | USB_REQ_TYPE_INTERFACE,
		USB_REQ_TYPE_TYPE | USB_REQ_TYPE_RECIPIENT,
		hid_control_request);
}

static usbd_device *usbd_dev;
static uint8_t usbd_control_buffer[150];

void usbInit(void)
{
	usbd_dev = usbd_init(&otgfs_usb_driver, &dev_descr, &config, usb_strings, 3, usbd_control_buffer, sizeof(usbd_control_buffer));
	usbd_register_set_config_callback(usbd_dev, usb_set_config);
}

void usbPoll(void)
{
	static const uint8_t *data;
	// poll read buffer
	usbd_poll(usbd_dev);
	// write pending data
	data = msg_out_data();
	if (data) {
		while ( usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_IN, data, 64) != 64 ) {}
	}
	data = u2f_out_data();
	if (data) {
		while ( usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_U2F_IN, data, 64) != 64 ) {}
	}
#if DEBUG_LINK
	// write pending debug data
	data = msg_debug_out_data();
	if (data) {
		while ( usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_DEBUG_IN, data, 64) != 64 ) {}
	}
#endif
}

void usbReconnect(void)
{
	usbd_disconnect(usbd_dev, 1);
	delay(1000);
	usbd_disconnect(usbd_dev, 0);
}

char usbTiny(char set)
{
	char old = tiny;
	tiny = set;
	return old;
}

void usbSleep(uint32_t millis)
{
	uint32_t start = system_millis;

	while ((system_millis - start) < millis) {
		usbd_poll(usbd_dev);
	}
}

uint16_t ccid_tx(void *tx, uint16_t len) {
	return usbd_ep_write_packet(usbd_dev, ENDPOINT_ADDRESS_CCID_IN, tx, len);
}
