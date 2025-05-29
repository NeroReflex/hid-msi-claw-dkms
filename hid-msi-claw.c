#include <linux/dmi.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/usb.h>

//#include "hid-ids.h"

#define MSI_CLAW_FEATURE_GAMEPAD_REPORT_ID 0x0f

#define MSI_CLAW_READ_SIZE 8

#define MSI_CLAW_GAME_CONTROL_DESC   0x05
#define MSI_CLAW_DEVICE_CONTROL_DESC 0x06

enum msi_claw_gamepad_mode {
	MSI_CLAW_GAMEPAD_MODE_OFFLINE = 0x00,
	MSI_CLAW_GAMEPAD_MODE_XINPUT = 0x01,
	MSI_CLAW_GAMEPAD_MODE_DINPUT = 0x02,
	MSI_CLAW_GAMEPAD_MODE_MSI = 0x03,
	MSI_CLAW_GAMEPAD_MODE_DESKTOP = 0x04,
	MSI_CLAW_GAMEPAD_MODE_BIOS = 0x05,
	MSI_CLAW_GAMEPAD_MODE_TESTING = 0x06,
};

static const bool gamepad_mode_debug = false;

static const struct {
	const char* name;
	const bool available;
} gamepad_mode_map[] = {
	{"offline", gamepad_mode_debug},
	{"xinput", true},
	{"dinput", gamepad_mode_debug},
	{"msi", gamepad_mode_debug},
	{"desktop", true},
	{"bios", gamepad_mode_debug},
	{"testing", gamepad_mode_debug},
};

enum msi_claw_mkeys_function {
	MSI_CLAW_MKEY_FUNCTION_MACRO = 0x00,
	MSI_CLAW_MKEY_FUNCTION_COMBINATION = 0x01,
};

static const char* mkeys_function_map[] =
{
	"macro",
	"combination",
};

enum msi_claw_command_type {
	MSI_CLAW_COMMAND_TYPE_ENTER_PROFILE_CONFIG = 0x01,
	MSI_CLAW_COMMAND_TYPE_EXIT_PROFILE_CONFIG = 0x02,
	MSI_CLAW_COMMAND_TYPE_WRITE_PROFILE = 0x03,
	MSI_CLAW_COMMAND_TYPE_READ_PROFILE = 0x04,
	MSI_CLAW_COMMAND_TYPE_READ_PROFILE_ACK = 0x05,
	MSI_CLAW_COMMAND_TYPE_ACK = 0x06,
	MSI_CLAW_COMMAND_TYPE_SWITCH_PROFILE = 0x07,
	MSI_CLAW_COMMAND_TYPE_WRITE_PROFILE_TO_EEPROM = 0x08,
	MSI_CLAW_COMMAND_TYPE_READ_FIRMWARE_VERSION = 0x09,
	MSI_CLAW_COMMAND_TYPE_READ_RGB_STATUS_ACK = 0x0a,
	MSI_CLAW_COMMAND_TYPE_READ_CURRENT_PROFILE = 0x0b,
	MSI_CLAW_COMMAND_TYPE_READ_CURRENT_PROFILE_ACK = 0x0c,
	MSI_CLAW_COMMAND_TYPE_READ_RGB_STATUS = 0x0d,
	MSI_CLAW_COMMAND_TYPE_SYNC_TO_ROM = 0x22,
	MSI_CLAW_COMMAND_TYPE_RESTORE_FROM_ROM = 0x23,
	MSI_CLAW_COMMAND_TYPE_SWITCH_MODE = 0x24,
	MSI_CLAW_COMMAND_TYPE_READ_GAMEPAD_MODE = 0x26,
	MSI_CLAW_COMMAND_TYPE_GAMEPAD_MODE_ACK = 0x27,
	MSI_CLAW_COMMAND_TYPE_RESET_DEVICE = 0x28,
	MSI_CLAW_COMMAND_TYPE_RGB_CONTROL = 0xe0,
	MSI_CLAW_COMMAND_TYPE_CALIBRATION_CONTROL = 0xfd,
	MSI_CLAW_COMMAND_TYPE_CALIBRATION_ACK = 0xff,
};

struct msi_claw_control_status {
	enum msi_claw_gamepad_mode gamepad_mode;
	enum msi_claw_mkeys_function mkeys_function;
};

struct msi_claw_drvdata {
	struct hid_device *hdev;
	struct input_dev *input;
	struct input_dev *tp_kbd_input;

	struct msi_claw_control_status *control;
};

static int msi_claw_write_cmd(struct hid_device *hdev, enum msi_claw_command_type cmdtype,
        u8 b1, u8 b2, u8 b3)
{
	int ret;
	const unsigned char buf[] = {
		MSI_CLAW_FEATURE_GAMEPAD_REPORT_ID, 0, 0, 0x3c,
		cmdtype, b1, b2, b3
	};
	unsigned char *dmabuf = kmemdup(buf, sizeof(buf), GFP_KERNEL);
	if (!dmabuf) {
		ret = -ENOMEM;
		hid_err(hdev, "hid-msi-claw failed to alloc dma buf: %d\n", ret);
		return ret;
	}

	ret = hid_hw_output_report(hdev, dmabuf, sizeof(buf));

	kfree(dmabuf);

	if (ret != sizeof(buf)) {
		hid_err(hdev, "hid-msi-claw failed to switch controller mode: %d\n", ret);
		return ret;
	}

	return 0;
}

static int msi_claw_read(struct hid_device *hdev, u8 *const buffer)
{
	int ret;

	unsigned char *dmabuf = kmemdup(buffer, MSI_CLAW_READ_SIZE, GFP_KERNEL);
	if (!dmabuf) {
		ret = -ENOMEM;
		hid_err(hdev, "hid-msi-claw failed to alloc dma buf: %d\n", ret);
		return ret;
	}

	ret = hid_hw_raw_request(hdev, 0x82, dmabuf, MSI_CLAW_READ_SIZE, HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
	if (ret >= 8) {
		hid_err(hdev, "hid-msi-claw read %d bytes: %02x %02x %02x %02x %02x %02x %02x %02x \n", ret,
			dmabuf[0], dmabuf[1], dmabuf[2], dmabuf[3], dmabuf[4], dmabuf[5], dmabuf[6], dmabuf[7]);
		memcpy((void*)buffer, dmabuf, 8);
		ret = 0;
	} else if (ret < 0) {
		hid_err(hdev, "hid-msi-claw failed to read: %d\n", ret);
		goto msi_claw_read_err;
	} else {
		hid_err(hdev, "hid-msi-claw read %d bytes\n", ret);
		ret = -EINVAL;
		goto msi_claw_read_err;
	}

msi_claw_read_err:
	kfree(dmabuf);

	return ret;
}

static int sync_to_rom(struct hid_device *hdev) {
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);
	int ret;

	if (!drvdata->control) {
		hid_err(hdev, "hid-msi-claw couldn't find control interface\n");
		ret = -ENODEV;
		return ret;
	}

	ret = msi_claw_write_cmd(hdev, MSI_CLAW_COMMAND_TYPE_SYNC_TO_ROM, 0x00, 0x00, 0x00);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed to send write request for switch controller mode: %d\n", ret);
		return ret;
	}

	return ret;
}

static int msi_claw_switch_gamepad_mode(struct hid_device *hdev, enum msi_claw_gamepad_mode mode,
	enum msi_claw_mkeys_function mkeys)
{
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);
	u8 buffer[MSI_CLAW_READ_SIZE] = {};
	const u8 mode_byte = (u8)mode;
	const u8 mkeys_byte = (u8)mkeys;
	const u8 unknown_byte = 0x00;

	int ret;

	if (!drvdata->control) {
		hid_err(hdev, "hid-msi-claw couldn't find control interface\n");
		ret = -ENODEV;
		return ret;
	}

	// 0f00003c240100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	ret = msi_claw_write_cmd(hdev, MSI_CLAW_COMMAND_TYPE_SWITCH_MODE, mode_byte, mkeys_byte, unknown_byte);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed to send write request for switch controller mode: %d\n", ret);
		return ret;
	}

	drvdata->control->gamepad_mode = mode;

	// 0f00003c260000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	ret = msi_claw_write_cmd(hdev, MSI_CLAW_COMMAND_TYPE_READ_GAMEPAD_MODE, (u8)0, (u8)0, (u8)0);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed to send read request for controller mode: %d\n", ret);
		return ret;
	}

	// here goes the actual read call and the check.
	// an example response is: 1000003c270100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	// wireshark shows 64 bytes, but it does so for host->device too and we know 8 bytes are to be sent.
	ret = msi_claw_read(hdev, buffer);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed to read: %d\n", ret);
		// return ret;
	}
	// TODO: uncomment the return above and this else
	else {
		if (buffer[0] != 0x10) {
			hid_err(hdev, "hid-msi-claw unexpected destination in readback buffer\n");
			//return -EINVAL;
		} else if (buffer[3] != (u8)0x3c) {
			hid_err(hdev, "hid-msi-claw not the correct data.\n");
		} else if (buffer[4] != (u8)MSI_CLAW_COMMAND_TYPE_GAMEPAD_MODE_ACK) {
			hid_err(hdev, "hid-msi-claw not command type ACK.\n");
		} else if (buffer[5] != mode_byte) {
			hid_err(hdev, "hid-msi-claw invalid gamepad mode.\n");
		} else if (buffer[6] != mkeys_byte) {
			hid_err(hdev, "hid-msi-claw invalid mkeys mode.\n");
		} else if (buffer[6] != unknown_byte) {
			hid_err(hdev, "hid-msi-claw invalid status.\n");
		}
	}

	// assuming the read result is the expected one
	drvdata->control->mkeys_function = mkeys;

	// the device now sends back 03 00 00 00 00 00 00 00 00
	
	// this command is always issued by the windows counterpart after a mode switch
	ret = sync_to_rom(hdev);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed the sync to rom command: %d\n", ret);
		return ret;
	}

	return 0;
}

static ssize_t gamepad_mode_available_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int ret = 0;
	int len = ARRAY_SIZE(gamepad_mode_map);

	for (int i = 0; i < len; i++)
	{
		if (!gamepad_mode_map[i].available)
			continue;

		ret += sysfs_emit_at(buf, ret, "%s", gamepad_mode_map[i].name);

		if (i < len-1)
			ret += sysfs_emit_at(buf, ret, " ");
	}
	ret += sysfs_emit_at(buf, ret, "\n");

	return ret;
}
static DEVICE_ATTR_RO(gamepad_mode_available);

static ssize_t gamepad_mode_current_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	return sysfs_emit(buf, "%s\n", gamepad_mode_map[drvdata->control->gamepad_mode].name);
}

static ssize_t gamepad_mode_current_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	enum msi_claw_gamepad_mode new_gamepad_mode = ARRAY_SIZE(gamepad_mode_map);
	ssize_t ret;

	if (!count) {
		ret = -EINVAL;
		goto gamepad_mode_current_store_err;
	}

	char* input = kmemdup(buf, count+1, GFP_KERNEL);
	if (!input) {
		ret = -ENOMEM;
		goto gamepad_mode_current_store_err;
	}

	input[count] = '\0';
	if (input[count-1] == '\n')
		input[count-1] = '\0';

	for (size_t i = 0; i < (size_t)new_gamepad_mode; i++)
		if ((!strcmp(input, gamepad_mode_map[i].name)) && (gamepad_mode_map[i].available))
			new_gamepad_mode = (enum msi_claw_gamepad_mode)i;

	kfree(input);

	if (new_gamepad_mode == ARRAY_SIZE(gamepad_mode_map)) {
		hid_err(hdev, "Invalid gamepad mode selected\n");
		ret= -EINVAL;
		goto gamepad_mode_current_store_err;
	}

	ret = msi_claw_switch_gamepad_mode(hdev, new_gamepad_mode, drvdata->control->mkeys_function);
	if (ret < 0) {
		hid_err(hdev, "Error changing gamepad mode: %d\n", (int)ret);
		goto gamepad_mode_current_store_err;
	}

	ret = count;

gamepad_mode_current_store_err:
	return ret;
}
static DEVICE_ATTR_RW(gamepad_mode_current);

static ssize_t mkeys_function_available_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int ret = 0;
	int len = ARRAY_SIZE(mkeys_function_map);

	for (int i = 0; i < len; i++)
	{
		ret += sysfs_emit_at(buf, ret, "%s", mkeys_function_map[i]);

		if (i < len-1)
			ret += sysfs_emit_at(buf, ret, " ");
	}
	ret += sysfs_emit_at(buf, ret, "\n");

	return ret;
}
static DEVICE_ATTR_RO(mkeys_function_available);

static ssize_t mkeys_function_current_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	return sysfs_emit(buf, "%s\n", mkeys_function_map[drvdata->control->mkeys_function]);
}

static ssize_t mkeys_function_current_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	enum msi_claw_mkeys_function new_mkeys_function = ARRAY_SIZE(mkeys_function_map);

	ssize_t ret;

	if (!count) {
		ret = -EINVAL;
		goto mkeys_function_current_store_err;
	}

	char* input = kmemdup(buf, count+1, GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	input[count] = '\0';
	if (input[count-1] == '\n')
		input[count-1] = '\0';

	for (size_t i = 0; i < (size_t)new_mkeys_function; i++)
		if (!strcmp(input, mkeys_function_map[i]))
			new_mkeys_function = i;

	kfree(input);

	if (new_mkeys_function == ARRAY_SIZE(mkeys_function_map)) {
		hid_err(hdev, "Invalid mkeys function selected\n");
		ret= -EINVAL;
		goto mkeys_function_current_store_err;
	}

	ret = msi_claw_switch_gamepad_mode(hdev, drvdata->control->gamepad_mode, new_mkeys_function);
	if (ret < 0) {
		hid_err(hdev, "Error changing mkeys function: %d\n", (int)ret);
		goto mkeys_function_current_store_err;
	}

	ret = count;

mkeys_function_current_store_err:
	return ret;
}
static DEVICE_ATTR_RW(mkeys_function_current);

static ssize_t debug_read_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hid_device *hdev = to_hid_device(dev);
	u8 buffer[MSI_CLAW_READ_SIZE] = {};

	const int res = msi_claw_read(hdev, buffer);

	return sysfs_emit(buf, "%d -> %02x%02x%02x%02x%02x%02x%02x%02x\n",
		res,
		buffer[0], buffer[1], buffer[2], buffer[3],
		buffer[4], buffer[5], buffer[6], buffer[7]
	);
}
static DEVICE_ATTR_RO(debug_read);

static int msi_claw_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int ret;
	struct msi_claw_drvdata *drvdata;

	if (!hid_is_usb(hdev)) {
		hid_err(hdev, "hid-msi-claw hid not usb\n");
		return -ENODEV;
	}

	drvdata = devm_kzalloc(&hdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (drvdata == NULL) {
		hid_err(hdev, "hid-msi-claw can't alloc descriptor\n");
		return -ENOMEM;
	}

	drvdata->control = NULL;

	hid_set_drvdata(hdev, drvdata);

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "hid-msi-claw hid parse failed: %d\n", ret);
		return ret;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
	if (ret) {
		hid_err(hdev, "hid-msi-claw hw start failed: %d\n", ret);
		return ret;
	}

	ret = hid_hw_open(hdev);
	if (ret) {
		hid_err(hdev, "hid-msi-claw failed to open HID device: %d\n", ret);
		goto err_stop_hw;
	}

//	hid_err(hdev, "hid-msi-claw on %d\n", (int)hdev->rdesc[0]);

	if (hdev->rdesc[0] == MSI_CLAW_DEVICE_CONTROL_DESC) {
		drvdata->control = devm_kzalloc(&hdev->dev, sizeof(*(drvdata->control)), GFP_KERNEL);
		if (drvdata->control == NULL) {
			hid_err(hdev, "hid-msi-claw can't alloc control interface data\n");
			ret = -ENOMEM;
			goto err_close;
		}

		drvdata->control->gamepad_mode = MSI_CLAW_GAMEPAD_MODE_XINPUT;
		drvdata->control->mkeys_function = MSI_CLAW_MKEY_FUNCTION_MACRO;

		ret = msi_claw_switch_gamepad_mode(hdev, drvdata->control->gamepad_mode, drvdata->control->mkeys_function);
		if (ret != 0) {
			hid_err(hdev, "hid-msi-claw failed to initialize controller mode: %d\n", ret);
			goto err_close;
		}

		ret = sysfs_create_file(&hdev->dev.kobj, &dev_attr_gamepad_mode_available.attr);
		if (ret) {
			hid_err(hdev, "hid-msi-claw failed to sysfs_create_file dev_attr_gamepad_mode_available: %d\n", ret);
			goto err_close;
		}

		ret = sysfs_create_file(&hdev->dev.kobj, &dev_attr_gamepad_mode_current.attr);
		if (ret) {
			hid_err(hdev, "hid-msi-claw failed to sysfs_create_file dev_attr_gamepad_mode_current: %d\n", ret);
			goto err_close;
		}

		ret = sysfs_create_file(&hdev->dev.kobj, &dev_attr_mkeys_function_available.attr);
		if (ret) {
			hid_err(hdev, "hid-msi-claw failed to sysfs_create_file dev_attr_mkeys_function_available: %d\n", ret);
			goto err_close;
		}

		ret = sysfs_create_file(&hdev->dev.kobj, &dev_attr_mkeys_function_current.attr);
		if (ret) {
			hid_err(hdev, "hid-msi-claw failed to sysfs_create_file dev_attr_mkeys_function_current: %d\n", ret);
			goto err_close;
		}

		ret = sysfs_create_file(&hdev->dev.kobj, &dev_attr_debug_read.attr);
		if (ret) {
			hid_err(hdev, "hid-msi-claw failed to sysfs_create_file dev_attr_debug_read: %d\n", ret);
			goto err_close;
		}
	}

	return 0;

err_close:
	hid_hw_close(hdev);
err_stop_hw:
	hid_hw_stop(hdev);
	return ret;
}

static void msi_claw_remove(struct hid_device *hdev)
{
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	if (drvdata->control) {
		sysfs_remove_file(&hdev->dev.kobj, &dev_attr_gamepad_mode_available.attr);
		sysfs_remove_file(&hdev->dev.kobj, &dev_attr_gamepad_mode_current.attr);
		sysfs_remove_file(&hdev->dev.kobj, &dev_attr_mkeys_function_available.attr);
		sysfs_remove_file(&hdev->dev.kobj, &dev_attr_mkeys_function_current.attr);
	}

	hid_hw_stop(hdev);
}

static int msi_claw_resume(struct hid_device *hdev) {
	struct msi_claw_drvdata *drvdata = hid_get_drvdata(hdev);

	int ret = 0;

	if (drvdata->control) {
		// the hardware needs some time to re-initialize
		ssleep(3);

		ret = msi_claw_switch_gamepad_mode(hdev, drvdata->control->gamepad_mode, drvdata->control->mkeys_function);
	}

	return ret;
}

static const struct hid_device_id msi_claw_devices[] = {
	{ HID_USB_DEVICE(0x0DB0, 0x1901) },
	{ }
};
MODULE_DEVICE_TABLE(hid, msi_claw_devices);

static struct hid_driver msi_claw_driver = {
	.name			= "hid-msi-claw",
	.id_table		= msi_claw_devices,
	.probe			= msi_claw_probe,
	.remove			= msi_claw_remove,
	.resume			= msi_claw_resume,
};
module_hid_driver(msi_claw_driver);

MODULE_LICENSE("GPL");
