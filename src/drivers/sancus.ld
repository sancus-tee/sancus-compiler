OUTPUT_FORMAT("elf32-msp430")
OUTPUT_ARCH("msp430")

SECTIONS
{
  $sm_text_sections
  $sm_mac_sections

  .text : {*(.text) *(.rodata)}
  .data : {*(.data)}
  .bss  :
  {
    *(.bss)
    $sm_data_sections
  }
}

$sm_symbols
