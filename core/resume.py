#!/usr/bin/env python3
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ResumeManager:
    """Manages resume capability for interrupted operations."""
    
    def __init__(self, target: str, output_dir: str = "outputs"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.state_file = self.output_dir / f"{target}_resume_state.json"
        self.state = self._load_state()
    
    def _load_state(self) -> Dict:
        """Load resume state from file."""
        if self.state_file.exists():
            try:
                with self.state_file.open("r") as f:
                    state = json.load(f)
                logger.info(f"Loaded resume state for {self.target}")
                return state
            except Exception as e:
                logger.error(f"Error loading resume state: {e}")
                return self._get_initial_state()
        else:
            return self._get_initial_state()
    
    def _get_initial_state(self) -> Dict:
        """Get initial resume state."""
        return {
            "target": self.target,
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "phases": {
                "reconnaissance": {
                    "status": "pending",
                    "started": None,
                    "completed": None,
                    "services": []
                },
                "exploitation": {
                    "status": "pending",
                    "started": None,
                    "completed": None,
                    "services": []
                },
                "post_exploitation": {
                    "status": "pending",
                    "started": None,
                    "completed": None,
                    "services": []
                },
                "reporting": {
                    "status": "pending",
                    "started": None,
                    "completed": None
                }
            },
            "completed_services": set(),
            "failed_services": set()
        }
    
    def _save_state(self):
        """Save current state to file."""
        try:
            # Convert sets to lists for JSON serialization
            state_to_save = self.state.copy()
            state_to_save["completed_services"] = list(self.state["completed_services"])
            state_to_save["failed_services"] = list(self.state["failed_services"])
            state_to_save["last_updated"] = datetime.now().isoformat()
            
            with self.state_file.open("w") as f:
                json.dump(state_to_save, f, indent=4)
            logger.info(f"Saved resume state for {self.target}")
        except Exception as e:
            logger.error(f"Error saving resume state: {e}")
    
    def start_phase(self, phase: str):
        """Mark a phase as started."""
        if phase in self.state["phases"]:
            self.state["phases"][phase]["status"] = "running"
            self.state["phases"][phase]["started"] = datetime.now().isoformat()
            self._save_state()
            logger.info(f"Started phase: {phase}")
    
    def complete_phase(self, phase: str):
        """Mark a phase as completed."""
        if phase in self.state["phases"]:
            self.state["phases"][phase]["status"] = "completed"
            self.state["phases"][phase]["completed"] = datetime.now().isoformat()
            self._save_state()
            logger.info(f"Completed phase: {phase}")
    
    def fail_phase(self, phase: str):
        """Mark a phase as failed."""
        if phase in self.state["phases"]:
            self.state["phases"][phase]["status"] = "failed"
            self._save_state()
            logger.info(f"Failed phase: {phase}")
    
    def add_completed_service(self, service: str):
        """Add a service to completed list."""
        self.state["completed_services"].add(service)
        self._save_state()
        logger.info(f"Added completed service: {service}")
    
    def add_failed_service(self, service: str):
        """Add a service to failed list."""
        self.state["failed_services"].add(service)
        self._save_state()
        logger.info(f"Added failed service: {service}")
    
    def get_pending_services(self, phase: str) -> List[str]:
        """Get list of pending services for a phase."""
        if phase == "reconnaissance":
            # For reconnaissance, check what services need scanning
            all_services = {"http", "ftp", "ssh", "smtp", "mysql", "smb", "telnet", "dns", "vnc", "snmp", "postgresql"}
            return list(all_services - self.state["completed_services"])
        elif phase == "exploitation":
            # For exploitation, check what services have recon data
            recon_services = self._get_services_with_recon_data()
            return list(recon_services - self.state["completed_services"])
        elif phase == "post_exploitation":
            # For post-exploitation, check what services have exploit data
            exploit_services = self._get_services_with_exploit_data()
            return list(exploit_services - self.state["completed_services"])
        else:
            return []
    
    def _get_services_with_recon_data(self) -> Set[str]:
        """Get services that have reconnaissance data."""
        services = set()
        metadata_files = list(self.output_dir.glob(f"{self.target}_*_metadata.json"))
        for file in metadata_files:
            service = file.stem.replace(f"{self.target}_", "").replace("_metadata", "")
            services.add(service.split("_")[0])
        return services
    
    def _get_services_with_exploit_data(self) -> Set[str]:
        """Get services that have exploitation data."""
        services = set()
        exploit_files = list(self.output_dir.glob(f"{self.target}_*_exploit.json"))
        for file in exploit_files:
            service = file.stem.replace(f"{self.target}_", "").replace("_exploit", "")
            services.add(service)
        return services
    
    def get_phase_status(self, phase: str) -> str:
        """Get status of a specific phase."""
        return self.state["phases"].get(phase, {}).get("status", "unknown")
    
    def is_phase_completed(self, phase: str) -> bool:
        """Check if a phase is completed."""
        return self.get_phase_status(phase) == "completed"
    
    def is_phase_running(self, phase: str) -> bool:
        """Check if a phase is running."""
        return self.get_phase_status(phase) == "running"
    
    def is_phase_pending(self, phase: str) -> bool:
        """Check if a phase is pending."""
        return self.get_phase_status(phase) == "pending"
    
    def get_completed_services(self) -> Set[str]:
        """Get set of completed services."""
        return self.state["completed_services"].copy()
    
    def get_failed_services(self) -> Set[str]:
        """Get set of failed services."""
        return self.state["failed_services"].copy()
    
    def get_progress_summary(self) -> Dict:
        """Get progress summary."""
        total_phases = len(self.state["phases"])
        completed_phases = sum(1 for phase in self.state["phases"].values() if phase["status"] == "completed")
        failed_phases = sum(1 for phase in self.state["phases"].values() if phase["status"] == "failed")
        
        return {
            "target": self.target,
            "total_phases": total_phases,
            "completed_phases": completed_phases,
            "failed_phases": failed_phases,
            "pending_phases": total_phases - completed_phases - failed_phases,
            "completion_percentage": (completed_phases / total_phases) * 100 if total_phases > 0 else 0,
            "completed_services": len(self.state["completed_services"]),
            "failed_services": len(self.state["failed_services"])
        }
    
    def can_resume(self) -> bool:
        """Check if operation can be resumed."""
        # Check if any phase is running or if there are pending phases
        for phase_name, phase_data in self.state["phases"].items():
            if phase_data["status"] in ["running", "pending"]:
                return True
        return False
    
    def get_next_phase(self) -> Optional[str]:
        """Get the next phase to run."""
        phase_order = ["reconnaissance", "exploitation", "post_exploitation", "reporting"]
        
        for phase in phase_order:
            if self.is_phase_pending(phase):
                return phase
            elif self.is_phase_running(phase):
                return phase
        
        return None
    
    def reset(self):
        """Reset resume state."""
        self.state = self._get_initial_state()
        self._save_state()
        logger.info(f"Reset resume state for {self.target}")
    
    def cleanup(self):
        """Clean up resume state file."""
        if self.state_file.exists():
            self.state_file.unlink()
            logger.info(f"Cleaned up resume state for {self.target}") 