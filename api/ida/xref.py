from api.interface import XrefType
from enum import IntEnum, IntFlag

"""
The following enums are carbon-copied from IDA SDK to describe categories of code/data xrefs. 
IDA handles the xrefs automatically and may delete an xref added by the user if it does not contain the #XREF_USER bit.
"""


class CodeRef(IntEnum):
    fl_U = 0  # unknown -- for compatibility with old versions. Should not be used anymore.
    fl_CF = 16  # Call Far - This xref creates a function at the referenced location
    fl_CN = 17  # Call Near - This xref creates a function at the referenced location
    fl_JF = 18  # Jump Far
    fl_JN = 19  # Jump Near
    fl_US_obsolete = 20  # User specified (obsolete)
    fl_F = 21  # Ordinary flow: used to specify execution flow to the next instruction.


class DataRef(IntEnum):
    dr_U = 0  # Unknown -- for compatibility with old versions. Should not be used anymore.
    dr_O = 1  # Offset - The reference uses 'offset' of data rather than its value or the reference
    # appeared because the OFFSET flag of the instruction is set. THe meaning of this type is IDP
    # independent.
    dr_W = 2  # Write access
    dr_R = 3  # Read access
    dr_T = 4  # Text (for forced operands only) - Name of data is used in manual operand
    dr_I = 5  # Informational (a derived java class references its base class informationally)
    dr_S = 6  # Reference to enum member (symbolic constant)


class XrefFlags(IntFlag):
    XREF_USER = 0x20  # Bit indicating user-defined xref. This should be combined with the above types, and xrefs
    # marked as such will not be deleted by IDA. Cannot be used for fl_F xrefs.
    XREF_TAIL = 0x40  # Reference to tail byte in extrn symbols
    XREF_BASE = 0x80  # Reference to the base part of an offset
    XREF_MASK = 0x1F  # Mask to get xref type
    XREF_PASTEND = 0x100  # Reference is past item. This bit may be passed to add_dref() functions but it won't be
    # saved in the database. It will prevent the destruction of eventual alignment directives.


class IDAXrefType(XrefType):
    TYPES = {
        0x00: 'Data_Unknown',
        0x01: 'Data_Offset',
        0x02: 'Data_Write',
        0x03: 'Data_Read',
        0x04: 'Data_Text',
        0x05: 'Data_Informational',
        0x10: 'Code_Far_Call',
        0x11: 'Code_Near_Call',
        0x12: 'Code_Far_Jump',
        0x13: 'Code_Near_Jump',
        0x14: 'Code_User',
        0x15: 'Ordinary_Flow'
    }

    @property
    def type(self):
        """Xref type, flags excluded."""
        return self._type & XrefFlags.XREF_MASK

    @property
    def flags(self):
        """Xref flags, type excluded."""
        return self._type ^ self.type

    @property
    def name(self):
        """Name of the xref type."""
        return self.TYPES[self._type]

    @property
    def is_code(self):
        return self._type & 0x10

    @property
    def is_data(self):
        return not self.is_code

    @property
    def is_unknown(self):
        return self.type == CodeRef.fl_U

    @property
    def is_offset(self):
        return self.type == DataRef.dr_O

    @property
    def is_write(self):
        return self.type == DataRef.dr_W

    @property
    def is_read(self):
        return self.type == DataRef.dr_R

    @property
    def is_text(self):
        return self.type == DataRef.dr_T

    @property
    def is_info(self):
        return self.type == DataRef.dr_I

    @property
    def is_far_call(self):
        return self.type == CodeRef.fl_CF

    @property
    def is_near_call(self):
        return self.type == CodeRef.fl_CN

    @property
    def is_far_jump(self):
        return self.type == CodeRef.fl_JF

    @property
    def is_near_jump(self):
        return self.type == CodeRef.fl_JN

    @property
    def is_flow(self):
        return self.type == CodeRef.fl_F

    @property
    def is_user(self):
        return self.flags & XrefFlags.XREF_USER

    @property
    def is_tail(self):
        return self.flags & XrefFlags.XREF_TAIL

    @property
    def is_base(self):
        return self.flags & XrefFlags.XREF_BASE

    @property
    def is_call(self):
        return self.is_far_call or self.is_near_call

    @property
    def is_jump(self):
        return self.is_far_jump or self.is_near_jump
