MEMORY
{
  sfr              : ORIGIN = 0x0000, LENGTH = 0x0010
  peripheral_8bit  : ORIGIN = 0x0010, LENGTH = 0x00f0
  peripheral_16bit : ORIGIN = 0x0100, LENGTH = 0x0100

  ram (wx)         : ORIGIN = 0x0200, LENGTH = $ram_length
  rom (rx)         : ORIGIN = $rom_origin, LENGTH = $rom_length-32

  vectors          : ORIGIN = 0xffe0, LENGTH = 32

  /* Remaining banks are absent */
  bsl              : ORIGIN = 0x0000, LENGTH = 0x0000
  infomem          : ORIGIN = 0x0000, LENGTH = 0x0000
  infob            : ORIGIN = 0x0000, LENGTH = 0x0000
  infoa            : ORIGIN = 0x0000, LENGTH = 0x0000
  infoc            : ORIGIN = 0x0000, LENGTH = 0x0000
  infod            : ORIGIN = 0x0000, LENGTH = 0x0000
  ram2 (wx)        : ORIGIN = 0x0000, LENGTH = 0x0000
  ram_mirror (wx)  : ORIGIN = 0x0000, LENGTH = 0x0000
  usbram (wx)      : ORIGIN = 0x0000, LENGTH = 0x0000
  far_rom          : ORIGIN = 0x00000000, LENGTH = 0x00000000
}

REGION_ALIAS("REGION_TEXT", rom);
REGION_ALIAS("REGION_DATA", ram);
REGION_ALIAS("REGION_FAR_ROM", far_rom);
