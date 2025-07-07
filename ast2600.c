/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2016 - 2020 Raptor Engineering, LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdlib.h>
#include <string.h>
#include "flash.h"
#include "programmer.h"
#include "platform/udelay.h"
#include "platform/pci.h"
#include "spi.h"
#include "hwaccess_physmap.h"
#include "hwaccess_x86_io.h"


#define PCI_VENDOR_ID_ASPEED		0x1a03

#define ASPEED_MEMMAP_SIZE		(128 * 1024)
#define ASPEED_P2A_OFFSET		0x10000

#define AST2600_SCU_APB_ADDR		0x1e6e2000
#define AST2600_SCU_APB_BRIDGE_OFFSET	(AST2600_SCU_APB_ADDR & 0xffff)
#define AST2600_SCU_PROT_KEY		0x00
#define AST2600_SCU_MISC_CTL		0x2c
#define AST2600_SCU_MISC_2_CTL		0x4c
#define AST2600_SCU_HW_STRAP		0x70

#define AST2600_SCU_PASSWORD		0x1688a8a8
#define AST2600_SCU_BOOT_SRC_MASK	0x3
#define AST2600_SCU_BOOT_SPI		0x2
#define AST2600_SCU_BOOT_NONE		0x3

#define AST2600_SMC_APB_ADDR		0x1e620000
#define AST2600_SMC_FMC00		0x00
#define AST2600_SMC_CE_CTL(N)		(0x10 + (N * 4))
#define AST2600_SMC_CE_SEG(N)		(0x30 + (N * 4))

#define AST2600_SMC_FLASH_MMIO_ADDR	0x20000000

#define AST2600_SPI_APB_ADDR		0x1e630000
#define AST2600_SPI_CFG			0x00
#define AST2600_SPI_CTL			0x04

#define AST2600_SPI_CFG_WRITE_EN	0x1
#define AST2600_SPI_CMD_FAST_R_MODE	0x1
#define AST2600_SPI_CMD_USER_MODE	0x3
#define AST2600_SPI_CMD_MASK		0x3
#define AST2600_SPI_STOP_CE_ACTIVE	(0x1 << 2)
#define AST2600_SPI_CPOL_1		(0x1 << 4)
#define AST2600_SPI_LSB_FIRST_CTRL	(0x1 << 5)
#define AST2600_SPI_SPEED_MASK		(0xf << 8)
#define AST2600_SPI_IO_MODE_MASK	(0x3 << 28)

#define AST2600_SPI_FLASH_MMIO_ADDR	0x30000000

#define AST2600_WDT_APB_ADDR		0x1e785000
#define AST2600_WDT_APB_BRIDGE_OFFSET	(AST2600_WDT_APB_ADDR & 0xffff)

#define AST2600_WDT1_CTL		0x0c

#define AST2600_WDT_RESET_MODE_MASK	(0x3 << 5)
#define AST2600_WDT_RESET_CPU_ONLY	(0x2 << 5)

// Default password from http://students.engr.scu.edu/~sschaeck/misc/aspeed-edac.html
#define AST2600_DEFAULT_PASSWORD	"5z&0VK{@`HW}H~V310=l=JB+M]IV-f;Sz98XfCA&Rp)i|Jo=2?IBN$QaQ2\"Kb|Ov"
// 5z&0VK{@`HW}H~V310=l=JB+M]IV-f;Sz98XfCA&Rp)i|Jo=2?IBN$QaQ2"Kb|Ov


struct ast2600_data {
	uint8_t *ast2600_device_bar;
	uint8_t ast2600_device_spi_bus;
	uint8_t ast2600_device_halt_cpu;
	uint8_t ast2600_device_resume_cpu;
	uint8_t ast2600_device_tickle_fw;
	uint32_t ast2600_device_flash_mmio_offset;
	uint32_t ast2600_device_host_mode;
	uint32_t ast2600_original_wdt_conf;
	uint32_t ast2600_serial_backdoor_access;
	uint32_t ast2600_active_peripheral_addr;
	uint32_t ast2600_read_timeout;
};

const struct dev_entry bmc_aspeed_ast2600[] = {
	{PCI_VENDOR_ID_ASPEED, 0x2000, OK, "ASPEED", "AST2600" },

	{0},
};

static int ast2600_spi_send_command(const struct flashctx *flash,
				   unsigned int writecnt, unsigned int readcnt,
				   const unsigned char *writearr,
				   unsigned char *readarr);

static const struct spi_master spi_master_ast2600 = {
	.features	= SPI_MASTER_4BA,
	.max_data_read	= 256,
	.max_data_write	= 256,
	.command	= ast2600_spi_send_command,
	.read		= default_spi_read,
	.write_256	= default_spi_write_256,
	.write_aai	= default_spi_write_aai,
};



static int ast2600_serialport_write(const char *buf, unsigned int writecnt)
{
	msg_pspew("Sending command: '%.*s'\n", writecnt, buf);
	return serialport_write((const unsigned char*)buf, writecnt);
}

static uint32_t ast2600_read_register_dword(uint32_t address, struct ast2600_data *ast_data)
{
	if (ast_data->ast2600_serial_backdoor_access) {
		char command_string[32];
		int command_string_len = 0;
		snprintf(command_string, 32, "r %x\r\n", ast_data->ast2600_active_peripheral_addr + address);
		command_string_len = strlen(command_string);
		sp_flush_incoming();
		ast2600_serialport_write(command_string, command_string_len);
		unsigned char read_buffer[48];
		memset(read_buffer, 0, sizeof read_buffer);
		msg_pspew("readbuffer len: '%d'\n", command_string_len + 8 + 3);
		if (!serialport_read_nonblock(read_buffer, command_string_len + 8 + 3, ast_data->ast2600_read_timeout, NULL)) {
			if (read_buffer[(command_string_len + 8 + 3) - 1] == '$') {
				read_buffer[command_string_len + 8] = 0;
			}
			msg_pspew("readbuffer: '%s'\n", read_buffer);
			return strtol((const char *)(read_buffer + command_string_len), NULL, 16);
		}
		return 0;
	}
	else {
		uint32_t extra_offset = 0;
		if (ast_data->ast2600_active_peripheral_addr == AST2600_SCU_APB_ADDR) {
			extra_offset = AST2600_SCU_APB_BRIDGE_OFFSET;
		}
		else if (ast_data->ast2600_active_peripheral_addr == AST2600_WDT_APB_ADDR) {
			extra_offset = AST2600_WDT_APB_BRIDGE_OFFSET;
		}
		return pci_mmio_readl(ast_data->ast2600_device_bar + ASPEED_P2A_OFFSET + extra_offset + address);
	}
}

static void ast2600_write_register_dword(uint32_t data, uint32_t address, struct ast2600_data *ast_data)
{
	if (ast_data->ast2600_serial_backdoor_access) {
		char command_string[32];
		int command_string_len = 0;
		snprintf(command_string, 32, "w %x %x\r\n", ast_data->ast2600_active_peripheral_addr + address, data);
		command_string_len = strlen(command_string);
		sp_flush_incoming();
		ast2600_serialport_write(command_string, command_string_len);
		unsigned char read_buffer[48];
		memset(read_buffer, 0, sizeof read_buffer);
		if (!serialport_read_nonblock(read_buffer, command_string_len + 3, 2000, NULL)) {
			if (read_buffer[(command_string_len + 3) - 1] == '$') {
				read_buffer[command_string_len] = 0;
			}
		}
	}
	else {
		uint32_t extra_offset = 0;
		if (ast_data->ast2600_active_peripheral_addr == AST2600_SCU_APB_ADDR) {
			extra_offset = AST2600_SCU_APB_BRIDGE_OFFSET;
		}
		else if (ast_data->ast2600_active_peripheral_addr == AST2600_WDT_APB_ADDR) {
			extra_offset = AST2600_WDT_APB_BRIDGE_OFFSET;
		}
		pci_mmio_writel(data, ast_data->ast2600_device_bar + ASPEED_P2A_OFFSET + extra_offset + address);
	}
}

static void ast2600_write_register_byte(uint8_t data, uint32_t address, struct ast2600_data *ast_data)
{
	if (ast_data->ast2600_serial_backdoor_access) {
		char command_string[32];
		int command_string_len = 0;
		snprintf(command_string, 32, "o %x %x\r\n", ast_data->ast2600_active_peripheral_addr + address, data);
		command_string_len = strlen(command_string);
		sp_flush_incoming();
		ast2600_serialport_write(command_string, command_string_len);
		unsigned char read_buffer[48];
		memset(read_buffer, 0, sizeof read_buffer);
		if (!serialport_read_nonblock(read_buffer, command_string_len + 3, 2000, NULL)) {
			if (read_buffer[(command_string_len + 3) - 1] == '$') {
				read_buffer[command_string_len] = 0;
			}
		}
	}
	else {
		uint32_t extra_offset = 0;
		if (ast_data->ast2600_active_peripheral_addr == AST2600_SCU_APB_ADDR) {
			extra_offset = AST2600_SCU_APB_BRIDGE_OFFSET;
		}
		else if (ast_data->ast2600_active_peripheral_addr == AST2600_WDT_APB_ADDR) {
			extra_offset = AST2600_WDT_APB_BRIDGE_OFFSET;
		}
		pci_mmio_writeb(data, ast_data->ast2600_device_bar + ASPEED_P2A_OFFSET + extra_offset + address);
	}
}

static int ast2600_set_a2b_bridge_scu(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_SCU_APB_ADDR & 0xffff0000, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_SCU_APB_ADDR;

	return 0;
}

static int ast2600_set_a2b_bridge_wdt(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_WDT_APB_ADDR & 0xffff0000, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_WDT_APB_ADDR;

	return 0;
}

static int ast2600_set_a2b_bridge_smc(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_SMC_APB_ADDR, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_SMC_APB_ADDR;

	return 0;
}

static int ast2600_set_a2b_bridge_spi(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_SPI_APB_ADDR, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_SPI_APB_ADDR;

	return 0;
}

static int ast2600_set_a2b_bridge_smc_flash(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_SMC_FLASH_MMIO_ADDR + ast_data->ast2600_device_flash_mmio_offset, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_SMC_FLASH_MMIO_ADDR;

	return 0;
}

static int ast2600_set_a2b_bridge_spi_flash(struct ast2600_data *ast_data)
{
	if (!ast_data->ast2600_serial_backdoor_access) {
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
		pci_mmio_writel(AST2600_SPI_FLASH_MMIO_ADDR, ast_data->ast2600_device_bar + 0xf004);
		pci_mmio_writel(0x1, ast_data->ast2600_device_bar + 0xf000);
	}
	ast_data->ast2600_active_peripheral_addr = AST2600_SPI_FLASH_MMIO_ADDR;

	return 0;
}

static int ast2600_disable_cpu(struct ast2600_data *ast_data) {
	uint32_t dword;

	if (ast_data->ast2600_device_halt_cpu) {
		dword = ast2600_read_register_dword(AST2600_SCU_HW_STRAP, ast_data);
		if (((dword & AST2600_SCU_BOOT_SRC_MASK) != AST2600_SCU_BOOT_SPI)
			&& ((dword & AST2600_SCU_BOOT_SRC_MASK) != AST2600_SCU_BOOT_NONE)) {	/* NONE permitted to allow for BMC recovery after Ctrl+C or crash */
			msg_perr("CPU halt requested but CPU firmware source is not SPI.\n");
			ast2600_write_register_dword(0x0, AST2600_SCU_PROT_KEY, ast_data);
			ast_data->ast2600_device_halt_cpu = 0;
			return 1;
		}

		/* Disable WDT from issuing full SoC reset
		 * Without this, OpenPOWER systems will crash when the GPIO blocks are reset on WDT timeout
		 */
		msg_pinfo("Configuring P2A bridge for WDT access\n");
		ast2600_set_a2b_bridge_wdt(ast_data);
		ast_data->ast2600_original_wdt_conf = ast2600_read_register_dword(AST2600_WDT1_CTL, ast_data);
		ast2600_write_register_dword((ast_data->ast2600_original_wdt_conf & ~AST2600_WDT_RESET_MODE_MASK) | AST2600_WDT_RESET_CPU_ONLY, AST2600_WDT1_CTL, ast_data);

		/* Disable CPU */
		ast2600_set_a2b_bridge_scu(ast_data);
		ast2600_write_register_dword((dword & ~AST2600_SCU_BOOT_SRC_MASK) | AST2600_SCU_BOOT_NONE, AST2600_SCU_HW_STRAP, ast_data);
	}

	return 0;
}

static int ast2600_enable_cpu(struct ast2600_data *ast_data) {
	uint32_t dword;

	if (ast_data->ast2600_device_halt_cpu && ast_data->ast2600_device_resume_cpu) {
		/* Re-enable CPU */
		ast2600_set_a2b_bridge_scu(ast_data);
		dword = ast2600_read_register_dword(AST2600_SCU_HW_STRAP, ast_data);
		ast2600_write_register_dword((dword & ~AST2600_SCU_BOOT_SRC_MASK) | AST2600_SCU_BOOT_SPI, AST2600_SCU_HW_STRAP, ast_data);

		/* Reset WDT configuration */
		ast2600_set_a2b_bridge_wdt(ast_data);
		ast2600_write_register_dword((ast_data->ast2600_original_wdt_conf & ~AST2600_WDT_RESET_MODE_MASK) | AST2600_WDT_RESET_CPU_ONLY, AST2600_WDT1_CTL, ast_data);
	}

	return 0;
}

static void ast2600_disable_backdoor_access(struct ast2600_data *ast_data)
{
	if (ast_data->ast2600_serial_backdoor_access) {
		/* Disable backdoor serial console */
		ast2600_serialport_write("q\r\n", 3);
	}
	else {
		/* Disable backdoor APB access */
		pci_mmio_writel(0x0, ast_data->ast2600_device_bar + 0xf000);
	}
}

static int ast2600_shutdown(void *data) {
	struct ast2600_data *ast_data = (struct ast2600_data *) data;

	/* Reactivate CPU if previously deactivated */
	ast2600_enable_cpu(ast_data);

	/* Shut down the backdoor access method(s) */
	ast2600_disable_backdoor_access(ast_data);

	return 0;
}

static int ast2600_init(const struct programmer_cfg *cfg)
{
	struct pci_dev *dev = NULL;
	uint32_t dword;
	uint8_t divisor;
	int timeout;

	char *arg;
	char *serial_port = NULL;
	char *ast2600_backdoor_password = NULL;
	struct ast2600_data *ast_data;

	// Serial backdoor settings
	int expected_rate = 1;
	int detected_rate = 0;

	ast_data = calloc(1, sizeof(*ast_data));
	if (!ast_data) {
		msg_perr("Unable to allocate space for SPI master data\n");
		return SPI_GENERIC_ERROR;
	}


	ast_data->ast2600_serial_backdoor_access = 0;
	serial_port = extract_programmer_param_str(cfg, "serial");
	if (serial_port) {
		ast_data->ast2600_serial_backdoor_access = 1;
	}

	if (ast_data->ast2600_serial_backdoor_access) {
		ast2600_backdoor_password = extract_programmer_param_str(cfg, "aspeed_vendor_backdoor_password");
		if (!ast2600_backdoor_password) {
			ast2600_backdoor_password = strdup(AST2600_DEFAULT_PASSWORD);
			msg_pinfo("No password specified with aspeed_vendor_backdoor_password, falling back to default.\n");
		}

		arg = extract_programmer_param_str(cfg, "high_speed_uart");
		if (arg && !strcmp(arg,"true"))
			expected_rate = 2;
		free(arg);
	}

	ast_data->ast2600_device_spi_bus = 0;
	arg = extract_programmer_param_str(cfg, "spibus");
	if (arg) {
		if (!strcmp(arg,"host"))
			ast_data->ast2600_device_host_mode = 1;
		else
			ast_data->ast2600_device_spi_bus = strtol(arg, NULL, 0);
	}
	free(arg);

	ast_data->ast2600_read_timeout = 2000;
	arg = extract_programmer_param_str(cfg, "hack_read_timeout");
	if (arg) {
		msg_pinfo("Using custom read timeout of %s ms\n", arg);
		ast_data->ast2600_read_timeout = strtol(arg, NULL, 0);
	}
	free(arg);


	ast_data->ast2600_device_halt_cpu = 0;
	arg = extract_programmer_param_str(cfg, "cpu");
	if (arg && !strcmp(arg,"pause")) {
		ast_data->ast2600_device_halt_cpu = 1;
		ast_data->ast2600_device_resume_cpu = 1;
	}
	if (arg && !strcmp(arg,"halt")) {
		ast_data->ast2600_device_halt_cpu = 1;
		ast_data->ast2600_device_resume_cpu = 0;
	}
	free(arg);

	arg = extract_programmer_param_str(cfg, "tickle");
	if (arg && !strcmp(arg,"true"))
		ast_data->ast2600_device_tickle_fw = 1;
	free(arg);

	if ((ast_data->ast2600_device_host_mode == 0) && ((ast_data->ast2600_device_spi_bus > 4) /* || (ast_data->ast2600_device_spi_bus < 0) */)) {
		if (ast_data->ast2600_serial_backdoor_access) {
			free(serial_port);
			free(ast2600_backdoor_password);
		}
		msg_perr("SPI bus number out of range!  Valid values are 0 - 4.\n");
		return 1;
	}

	if (ast_data->ast2600_serial_backdoor_access) {
		sp_fd = sp_openserport(serial_port, 115200);
		if (sp_fd == SER_INV_FD) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to open specified serial port!\n");
			return 1;
		}
		ast2600_serialport_write("q\r\n", 3);
		default_delay(500);
		ast2600_serialport_write("q\r\n", 3);
		if (serialport_shutdown(NULL)) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to close serial port prior to reopening at alternate baud rate!\n");
			return 1;
		}
		sp_fd = sp_openserport(serial_port, 921600);
		if (sp_fd == SER_INV_FD) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to reopen serial port at alternate baud rate!\n");
			return 1;
		}
		ast2600_serialport_write("q\r\n", 3);
		default_delay(500);
		ast2600_serialport_write("q\r\n", 3);
		if (serialport_shutdown(NULL)) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to close serial port prior to reopening at backdoor password transmission baud rate!\n");
			return 1;
		}
		sp_fd = sp_openserport(serial_port, 1200);
		if (sp_fd == SER_INV_FD) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to reopen serial port at backdoor password transmission baud rate!\n");
			return 1;
		}
		msg_pinfo("Sending vendor serial backdoor password... ");
		ast2600_serialport_write(ast2600_backdoor_password, strlen(ast2600_backdoor_password));
		msg_pinfo("done.\n");
		msg_pinfo("Waiting for response... ");
		timeout = 2000;		// 2 seconds
		while (1) {
			unsigned char read_buffer[1];
			if (!serialport_read_nonblock(read_buffer, 1, 1, NULL)) {
				if (read_buffer[0] == '$') {
					break;
				}
			}
			timeout--;
			if (timeout <= 0) {
				msg_pinfo("timeout!\n");
				free(serial_port);
				free(ast2600_backdoor_password);
				msg_perr("Device not responding!  Not connected or in lockdown mode (SCU2C bit 10 set)?\n");
				return 1;
			}
		}
		msg_pinfo("done.\n");
		if (serialport_shutdown(NULL)) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to close serial port prior to reopening at transfer baud rate!\n");
			return 1;
		}
		sp_fd = sp_openserport(serial_port, 115200);
		if (sp_fd == SER_INV_FD) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Unable to reopen serial port at transfer baud rate!\n");
			return 1;
		}
		internal_sleep(500000);
		// Detect baud rate
		sp_flush_incoming();
		ast2600_serialport_write("\r\n", 2);
		default_delay(500);
		sp_flush_incoming();
		ast2600_serialport_write("\r\n", 2);
		unsigned char read_buffer[48];
		memset(read_buffer, 0, sizeof read_buffer);
		if (!serialport_read_nonblock(read_buffer, 2 + 3, 2000, NULL)) {
			if (read_buffer[(2 + 3) - 1] == '$') {
				msg_pinfo("Detected 115200 baud interface\n");
				detected_rate = 1;
			} 
		}
		if (!detected_rate) {
			if (serialport_shutdown(NULL)) {
				free(serial_port);
				free(ast2600_backdoor_password);
				msg_perr("Unable to close serial port prior to reopening at alternate baud rate!\n");
				return 1;
			}
			sp_fd = sp_openserport(serial_port, 921600);
			if (sp_fd == SER_INV_FD) {
				free(serial_port);
				free(ast2600_backdoor_password);
				msg_perr("Unable to reopen serial port at alternate baud rate!\n");
				return 1;
			}

			sp_flush_incoming();
			ast2600_serialport_write("\r\n", 2);
			default_delay(500);
			sp_flush_incoming();
			ast2600_serialport_write("\r\n", 2);
			memset(read_buffer, 0, sizeof read_buffer);
			if (!serialport_read_nonblock(read_buffer, 2 + 3, 2000, NULL)) {
				if (read_buffer[(2 + 3) - 1] == '$') {
					msg_pinfo("Detected 921600 baud interface\n");
					detected_rate = 2;
				}
			}
		}
		if (!detected_rate) {
			free(serial_port);
			free(ast2600_backdoor_password);
			msg_perr("Device not responding on expected baud rate.  Faulty connection / power stability issue? %d  1111\n", detected_rate);
			return 1;
		}
	}
	else {
		if (rget_io_perms()) {
			free(serial_port);
			free(ast2600_backdoor_password);
			return 1;
		}

		dev = pcidev_init(cfg, bmc_aspeed_ast2600, PCI_BASE_ADDRESS_1);
		if (!dev) {
			free(serial_port);
			free(ast2600_backdoor_password);
			return 1;
		}

		uintptr_t io_base_addr = pcidev_readbar(dev, PCI_BASE_ADDRESS_1);
		if (!io_base_addr) {
			free(serial_port);
			free(ast2600_backdoor_password);
			return 1;
		}

		msg_pinfo("Detected ASPEED MMIO base address: %p.\n", (void*)io_base_addr);

		ast_data->ast2600_device_bar = rphysmap("ASPEED", io_base_addr, ASPEED_MEMMAP_SIZE);
		if (ast_data->ast2600_device_bar == ERROR_PTR) {
			free(serial_port);
			free(ast2600_backdoor_password);
			return 1;
		}

	        if (register_shutdown(ast2600_shutdown, dev)) {
			free(serial_port);
			free(ast2600_backdoor_password);
	                return 1;
		}

		io_base_addr += ASPEED_P2A_OFFSET;
		msg_pinfo("ASPEED P2A base address: %p.\n", (void*)io_base_addr);
	}

	msg_pinfo("Configuring P2A bridge for SCU access\n");
	ast2600_set_a2b_bridge_scu(ast_data);
	ast2600_write_register_dword(AST2600_SCU_PASSWORD, AST2600_SCU_PROT_KEY, ast_data);

	if (ast_data->ast2600_serial_backdoor_access) {
		if (detected_rate != expected_rate) {
			msg_pinfo("Configuring interface baud rate\n");

			dword = ast2600_read_register_dword(AST2600_SCU_MISC_2_CTL, ast_data);
			if (expected_rate == 1) {
				ast2600_write_register_dword(dword & ~(0x1 << 30), AST2600_SCU_MISC_2_CTL, ast_data);
			}
			else if (expected_rate == 2) {
				ast2600_write_register_dword(dword | (0x1 << 30), AST2600_SCU_MISC_2_CTL, ast_data);
			}

			if (serialport_shutdown(NULL)) {
				free(serial_port);
				free(ast2600_backdoor_password);
				msg_perr("Unable to close serial port prior to reopening at final baud rate!\n");
				return 1;
			}
			if (expected_rate == 1) {
				sp_fd = sp_openserport(serial_port, 115200);
			}
			else if (expected_rate == 2) {
				sp_fd = sp_openserport(serial_port, 921600);
			}
			if (sp_fd == SER_INV_FD) {
				free(serial_port);
				free(ast2600_backdoor_password);
				msg_perr("Unable to reopen serial port at final baud rate!\n");
				return 1;
			}
		}
	}

	free(serial_port);
	free(ast2600_backdoor_password);

	dword = ast2600_read_register_dword(AST2600_SCU_MISC_CTL, ast_data);
	ast2600_write_register_dword(dword & ~((0x1 << 24) | (0x2 << 22)), AST2600_SCU_MISC_CTL, ast_data);

	/* Halt CPU if requested */
	if (ast2600_disable_cpu(ast_data)) {
		ast2600_disable_backdoor_access(ast_data);
		return 1;
	}

	msg_pinfo("Configuring P2A bridge for SMC access\n");
	ast2600_set_a2b_bridge_smc(ast_data);

	if (ast_data->ast2600_device_host_mode) {
		msg_pinfo("Configuring P2A bridge for SPI access\n");
		ast2600_set_a2b_bridge_spi(ast_data);

		divisor = 0;	/* Slowest speed for now */

		dword = ast2600_read_register_dword(AST2600_SPI_CTL, ast_data);
		dword &= ~AST2600_SPI_SPEED_MASK;
		dword |= (divisor << 8);
		dword &= ~AST2600_SPI_CPOL_1;
		dword &= ~AST2600_SPI_LSB_FIRST_CTRL;	/* MSB first */
		dword &= ~AST2600_SPI_IO_MODE_MASK;	/* Single bit I/O mode */
		ast2600_write_register_dword(dword, AST2600_SPI_CTL, ast_data);
	}
	else {
		dword = ast2600_read_register_dword(AST2600_SMC_FMC00, ast_data);
		uint32_t calculated = ((dword >> (ast_data->ast2600_device_spi_bus * 2)) & 0x3);
		if ( calculated != 0x2) {
			msg_perr("CE%01x Flash type is not SPI! (dword = %x) (%x != %x) \n", ast_data->ast2600_device_spi_bus, dword, calculated, 0x2);
			ast2600_disable_backdoor_access(ast_data);
			return 1;
		}

		msg_pinfo("Enabling CE%01x write\n", ast_data->ast2600_device_spi_bus);
		dword = ast2600_read_register_dword(AST2600_SMC_FMC00, ast_data);
		ast2600_write_register_dword(dword | (0x1 << (16 + ast_data->ast2600_device_spi_bus)), AST2600_SMC_FMC00, ast_data);

		dword = ast2600_read_register_dword(AST2600_SMC_CE_SEG(ast_data->ast2600_device_spi_bus), ast_data);
		ast_data->ast2600_device_flash_mmio_offset = ((dword >> 16) & 0x3f) * 0x800000;
		msg_pinfo("Using CE%01x offset 0x%08x\n", ast_data->ast2600_device_spi_bus, ast_data->ast2600_device_flash_mmio_offset);
	}

	register_spi_master(&spi_master_ast2600, ast_data);

	return 0;
}

static void ast2600_spi_xfer_data(const struct flashctx *flash,
				   unsigned int writecnt, unsigned int readcnt,
				   const unsigned char *writearr,
				   unsigned char *readarr)
{
	unsigned int i;
	uint32_t dword;
	struct ast2600_data *ast_data = flash->mst->spi.data;
	for (i = 0; i < writecnt; i++)
		msg_pspew("[%02x]", writearr[i]);
	msg_pspew("\n");

	for (i = 0; i < writecnt; i=i+4) {
		if ((writecnt - i) < 4)
			break;
		dword = writearr[i];
		dword |= writearr[i + 1] << 8;
		dword |= writearr[i + 2] << 16;
		dword |= writearr[i + 3] << 24;
		ast2600_write_register_dword(dword, 0, ast_data);
	}
	for (; i < writecnt; i++)
		ast2600_write_register_byte(writearr[i], 0, ast_data);
	default_delay(1);
	for (i = 0; i < readcnt;) {
		dword = ast2600_read_register_dword(0, ast_data);
		if (i < readcnt)
			readarr[i] = dword & 0xff;
		i++;
		if (i < readcnt)
			readarr[i] = (dword >> 8) & 0xff;
		i++;
		if (i < readcnt)
			readarr[i] = (dword >> 16) & 0xff;
		i++;
		if (i < readcnt)
			readarr[i] = (dword >> 24) & 0xff;
		i++;
	}

	for (i = 0; i < readcnt; i++)
		msg_pspew("[%02x]", readarr[i]);
	msg_pspew("\n");
}

/* Returns 0 upon success, a negative number upon errors. */
static int ast2600_spi_send_command(const struct flashctx *flash,
				   unsigned int writecnt, unsigned int readcnt,
				   const unsigned char *writearr,
				   unsigned char *readarr)
{
	uint32_t dword;
	struct ast2600_data *ast_data = flash->mst->spi.data;

	msg_pspew("%s, cmd=0x%02x, writecnt=%d, readcnt=%d\n", __func__, *writearr, writecnt, readcnt);

	if (ast_data->ast2600_device_host_mode) {
		/* Set up user command mode */
		ast2600_set_a2b_bridge_spi(ast_data);
		dword = ast2600_read_register_dword(AST2600_SPI_CFG, ast_data);
		ast2600_write_register_dword(dword | AST2600_SPI_CFG_WRITE_EN, AST2600_SPI_CFG, ast_data);
		dword = ast2600_read_register_dword(AST2600_SPI_CTL, ast_data);
		ast2600_write_register_dword(dword | AST2600_SPI_CMD_USER_MODE, AST2600_SPI_CTL, ast_data);

	        /* Transfer data */
		ast2600_set_a2b_bridge_spi_flash(ast_data);
		ast2600_spi_xfer_data(flash, writecnt, readcnt, writearr, readarr);

		/* Tear down user command mode */
		ast2600_set_a2b_bridge_spi(ast_data);
		dword = ast2600_read_register_dword(AST2600_SPI_CTL, ast_data);
		ast2600_write_register_dword((dword & ~AST2600_SPI_CMD_MASK) | AST2600_SPI_CMD_FAST_R_MODE, AST2600_SPI_CTL, ast_data);
		dword = ast2600_read_register_dword(AST2600_SPI_CFG, ast_data);
		ast2600_write_register_dword(dword & ~AST2600_SPI_CFG_WRITE_EN, AST2600_SPI_CFG, ast_data);
	}
	else {
		/* Set up user command mode */
		ast2600_set_a2b_bridge_smc(ast_data);
		dword = ast2600_read_register_dword(AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		ast2600_write_register_dword(dword | AST2600_SPI_CMD_USER_MODE, AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		dword = ast2600_read_register_dword(AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		ast2600_write_register_dword(dword & ~AST2600_SPI_STOP_CE_ACTIVE, AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);

		/* Transfer data */
		ast2600_set_a2b_bridge_smc_flash(ast_data);
		ast2600_spi_xfer_data(flash, writecnt, readcnt, writearr, readarr);

		/* Tear down user command mode */
		ast2600_set_a2b_bridge_smc(ast_data);
		dword = ast2600_read_register_dword(AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		ast2600_write_register_dword(dword | AST2600_SPI_STOP_CE_ACTIVE, AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		dword = ast2600_read_register_dword(AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
		ast2600_write_register_dword((dword & ~AST2600_SPI_CMD_MASK) | AST2600_SPI_CMD_FAST_R_MODE, AST2600_SMC_CE_CTL(ast_data->ast2600_device_spi_bus), ast_data);
	}

	if (ast_data->ast2600_device_tickle_fw) {
		ast2600_enable_cpu(ast_data);
		default_delay(100);
		ast2600_disable_cpu(ast_data);
	}

	return 0;
}

const struct programmer_entry programmer_ast2600_spi = {
	.name			= "ast2600",
	.type			= PCI,
	.devs.dev		= bmc_aspeed_ast2600,
	.init			= ast2600_init,
};

