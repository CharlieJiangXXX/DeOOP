from pydantic import BaseModel
from typing import Optional


class LLVMIrBackendOptions(BaseModel):
    filterDebugInfo: bool
    filterIRMetadata: bool
    filterAttributes: bool
    filterComments: bool
    noDiscardValueNames: Optional[bool] = None
    demangle: bool
