#source: attr-gnu-4-5.s -32 -EB
#source: attr-gnu-4-1.s -32 -EB
#ld: -r -melf32btsmip
#readelf: -A

Attribute Section: gnu
File Attributes
  Tag_GNU_MIPS_ABI_FP: Hard float \(double precision\)

MIPS ABI Flags Version: 0

ISA: MIPS.*
GPR size: .*
CPR1 size: .*
CPR2 size: 0
FP ABI: Hard float \(double precision\)
ISA Extension: None
ASEs:
	None
FLAGS 1: 0000000.
FLAGS 2: 00000000
