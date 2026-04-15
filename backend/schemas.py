from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DevSchedule(BaseModel):
    available_hours_per_week: int = 40
    sprint_hours_remaining: int = 20
    work_days: List[str] = ["monday", "tuesday", "wednesday", "thursday", "friday"]


class TeamMember(BaseModel):
    name: str
    email: str
    role: str = ""
    linkedin_url: str = ""
    professional_summary: str = ""
    expertise: List[str]
    availability_notes: str = ""
    current_load: int = 0
    schedule: DevSchedule = DevSchedule()


class SystemInfo(BaseModel):
    name: str
    tier: str
    regulatory: List[str]
    owner: str = "security-team"
    dependencies: List[str] = []


class MaintenanceWindow(BaseModel):
    day: str
    time: str = "02:00"
    duration_hours: int = 4


class VendorAdvisory(BaseModel):
    advisory_id: str = ""
    title: str = ""
    severity: str = "medium"
    cve_ids: List[str] = []
    affected_packages: List[str] = []
    summary: str = ""
    url: str = ""
    published: str = ""


class InternalDoc(BaseModel):
    doc_id: str = ""
    title: str = ""
    systems: List[str] = []
    tags: List[str] = []
    criticality: str = ""
    content: str = ""


class DependencyEdge(BaseModel):
    source: str
    target: str
    relation: str = "depends_on"


class AnalyzeRequest(BaseModel):
    packages: Dict[str, str] = {}
    va_cve_ids: List[str] = []
    system_info: SystemInfo
    maintenance_windows: List[MaintenanceWindow] = []
    team_members: List[TeamMember] = []
    vendor_advisories: List[VendorAdvisory] = []
    internal_docs: List[InternalDoc] = []
    dependency_graph: List[DependencyEdge] = []
    exploit_language: str = "python"
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None


class TeamProfileRequest(BaseModel):
    name: str
    email: str
    role: str = ""
    linkedin_url: str = ""
    professional_summary: str = ""
    expertise: List[str] = []
    availability_notes: str = ""
    current_load: int = 0
    schedule: DevSchedule = DevSchedule()


class ScanRecordRequest(BaseModel):
    label: str
    system_name: str = ""
    counts: Dict[str, int] = {}
    request_payload: Dict[str, Any] = {}
    result_payload: Dict[str, Any] = {}


class NaturalLanguageConfigRequest(BaseModel):
    text: str
    current_system_info: Optional[SystemInfo] = None
    current_maintenance_windows: List[MaintenanceWindow] = []
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None


class AnalysisConfigPayload(BaseModel):
    packages: Dict[str, str] = {}
    va_cve_ids: List[str] = []
    system_info: Optional[SystemInfo] = None
    maintenance_windows: List[MaintenanceWindow] = []
    team_members: List[TeamMember] = []
    vendor_advisories: List[VendorAdvisory] = []
    internal_docs: List[InternalDoc] = []
    dependency_graph: List[DependencyEdge] = []
    exploit_language: str = "python"
    api_keys: Dict[str, str] = {}
    nl_text: str = ""


class ExploitRequest(BaseModel):
    cve_id: str
    description: str = ""
    full_research: str = ""
    package: str = ""
    version: str = ""
    language: str = "python"
    cvss: float = 5.0
    references: List[str] = []
    research_grounded: bool = False
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
