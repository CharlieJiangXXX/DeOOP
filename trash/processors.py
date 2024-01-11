from enum import Enum

class AlphaSeries(Enum):
    ALPHA_BIG_ENDIAN = "alphab"
    ALPHA_LITTLE_ENDIAN = "alphal"

class AnalogDevices(Enum):
    ANALOG_ADSP_218X = "ad218x"

class AngstremDevices(Enum):
    ANGSTREM_KR1878 = "kr1878"


class ArmProcessors(Enum):
    ARM_LITTLE_ENDIAN = "ARM"
    ARM_BIG_ENDIAN = "ARMB"

class AtmelAVRSeries(Enum):
    ATMEL_AVR = "AVR"

class DecSeries(Enum):
    DEC_PDP11 = "PDP11"

class EfiProcessors(Enum):
    EFI_BYTECODE = "ebc"

class FujitsuF2MC(Enum):
    FUJITSU_F2MC_16L = "F2MC16L"
    FUJITSU_F2MC_16LX = "F2MC16LX"

class Fujitsu32FR(Enum):
    FUJITSU_FR_32BIT = "fr"

class HitachiH8(Enum):
    HITACHI_H8_300H_NORMAL = "h8300"
    HITACHI_H8_300H_ADVANCED = "h8300a"
    HITACHI_H8S_NORMAL = "h8s300"
    HITACHI_H8S_ADVANCED = "h8s300a"
    HITACHI_H8SX_NORMAL = "h8sxn"
    HITACHI_H8SX_MIDDLE = "h8sxm"
    HITACHI_H8SX_ADVANCED = "h8sxa"
    HITACHI_H8SX_MAX = "h8sx"
    RENESAS_H8_3687 = "h8368"



class ProcessorFamily(Enum):
    INTEL = "Intel"
    AMD = "AMD"
    ZILOG = "Zilog"
    HITACHI = "Hitachi"
    MOTOROLA = "Motorola"
    DEC = "DEC"
    MOS = "MOS"
    POWERPC = "PowerPC"
    ARM = "ARM"
    TMS = "TMS"
    RENESAS = "Renesas"
    ATMEL = "ATMEL"
    MIPS = "MIPS"
    HITACHI_H8 = "Hitachi H8"
    MICROCHIP = "Microchip"
    SPARC = "SPARC"
    ALPHA = "ALPHA"
    HP = "HP"
    DSP56K = "DSP 56K"
    SIEMENS = "Siemens"
    SGS_THOMSON = "SGS-Thomson"
    MITSUBISHI = "Mitsubishi"
    FUJITSU = "Fujitsu"
    ANGSTREM = "Angstrem"
    ANALOG_DEVICES = "Analog Devices"
    INFINEON = "Infineon"
    EFI = "EFI"
    TEXAS_INSTRUMENTS = "Texas Instruments"

class IntelProcessors(Enum):
    INTEL_8086 = "8086"
    INTEL_80286_REAL = "80286r"
    INTEL_80286_PROT = "80286p"
    INTEL_80386_REAL = "80386r"
    INTEL_80386_PROT = "80386p"
    INTEL_80486_REAL = "80486r"
    INTEL_80486_PROT = "80486p"
    INTEL_80586_REAL = "80586r"
    INTEL_80586_PROT = "80586p"
    INTEL_80686_PROT = "80686p"
    INTEL_8085 = "8085"
    INTEL_8051 = "8051"
    INTEL_80196 = "80196"
    INTEL_80196NP = "80196NP"
    INTEL_PENTIUM2 = "p2"
    INTEL_PENTIUM3 = "p3"
    INTEL_PENTIUM4 = "p4"
    INTEL_IA64_LITTLE = "ia64l"
    INTEL_IA64_BIG = "ia64b"

class AmdProcessors(Enum):
    AMD_K6_2 = "k62"
    AMD_ATHLON = "athlon"

class ZilogProcessors(Enum):
    ZILOG_80 = "z80"
    ZILOG_180 = "z180"
    ZILOG_380 = "z380"
    ZILOG_8 = "z8"

class HitachiProcessors(Enum):
    HITACHI_64180 = "64180"
    HITACHI_6301 = "6301"
    HITACHI_6303 = "6303"

class MotorolaProcessors(Enum):
    MOTOROLA_68000 = "68000"
    MOTOROLA_68010 = "68010"
    MOTOROLA_68020 = "68020"
    MOTOROLA_68030 = "68030"
    MOTOROLA_68040 = "68040"
    MOTOROLA_68330 = "68330"
    MOTOROLA_68882 = "68882"
    MOTOROLA_68851 = "68851"
    MOTOROLA_68020EX = "68020EX"
    MOTOROLA_COLDFIRE = "colfire"
    MOTOROLA_68K = "68K"
    MOTOROLA_6800 = "6800"
    MOTOROLA_6801 = "6801"
    MOTOROLA_6803 = "6803"
    MOTOROLA_6805 = "6805"
    MOTOROLA_6808 = "6808"
    MOTOROLA_6809 = "6809"
    MOTOROLA_6811 = "6811"
    MOTOROLA_6812 = "6812"
    MOTOROLA_HCS12 = "hcs12"
    MOTOROLA_6816 = "6816"



class MosProcessors(Enum):
    MOS_6502 = "m6502"
    MOS_65C02 = "m65c02"

class PowerPcProcessors(Enum):
    POWERPC_BIG = "ppc"
    POWERPC_LITTLE = "ppcl"



class TmsProcessors(Enum):
    TMS_320C2 = "tms320c2"
    TMS_320C5 = "tms320c5"
    TMS_320C6 = "tms320c6"
    TMS_320C3 = "tms320c3"
    TMS_320C54 = "tms32054"
    TMS_320C55 = "tms32055"

class RenesasProcessors(Enum):
    RENESAS_SH3_LITTLE = "sh3"
    RENESAS_SH3_BIG = "sh3b"
    RENESAS_SH4_LITTLE = "sh4"
    RENESAS_SH4_BIG = "sh4b"
    RENESAS_SH2A_BIG = "sh2a"



class MipsProcessors(Enum):
    MIPS_LITTLE = "mipsl"
    MIPS_BIG = "mipsb"
    MIPS_RSP_LITTLE = "mipsrl"
    MIPS_RSP_BIG = "mipsr"
    MIPS_R5900_LITTLE = "r5900l"
    MIPS_R5900_BIG = "r5900r"



class MicrochipProcessors(Enum):
    MICROCHIP_12 = "pic12cxx"
    MICROCHIP_14 = "pic16cxx"
    MICROCHIP_16 = "pic18cxx"

class SparcProcessors(Enum):
    SPARC_BIG = "sparcb"
    SPARC_LITTLE = "sparcl"



class HpProcessors(Enum):
    HP_PA_RISC = "hppa"

class Dsp56kProcessors(Enum):
    DSP_5600X = "dsp56k"
    DSP_561XX = "dsp561xx"
    DSP_563XX = "dsp563xx"
    DSP_566XX = "dsp566xx"

class SiemensProcessors(Enum):
    SIEMENS_C166 = "c166"
    SIEMENS_C166V1 = "c166v1"
    SIEMENS_C166V2 = "c166v2"
    SIEMENS_ST10 = "st10"
    SIEMENS_SUPER10 = "super10"

class SgsThomsonProcessors(Enum):
    SGS_THOMSON_ST20_C1 = "st20"
    SGS_THOMSON_ST20_C2_C4 = "st20c4"

class MitsubishiProcessors(Enum):
    MITSUBISHI_16BIT = "m7700"
    MITSUBISHI_16BIT_ADVANCED = "m7750"
    MITSUBISHI_32BIT = "m32r"
    MITSUBISHI_32BIT_EXTENDED = "m32rx"
    MITSUBISHI_M7900 = "m7900"







class InfineonProcessors(Enum):
    INFINEON_TRICORE = "tricore"



class TexasInstrumentsProcessors(Enum):
    TEXAS_INSTRUMENTS_MSP430 = "msp430"