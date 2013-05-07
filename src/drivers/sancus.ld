OUTPUT_FORMAT("elf32-msp430")
OUTPUT_ARCH("msp430")

SECTIONS
{
  $spm_text_sections
  $spm_hmac_sections
  $spm_data_sections

  .text : {*(.text) *(.rodata)}
  .data : {*(.data)}
  .bss  : {*(.bss)}
}

$spm_symbols
