"""File Integrity Monitor.

Monitors critical agent files for unauthorized modifications using SHA256 checksums.

SAFETY NOTE:
- This module only reads files and computes hashes
- It does NOT modify any files unless auto_restore is explicitly enabled
- All changes are logged for audit purposes

Reference:
- https://github.com/prompt-security/clawsec
- https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/
"""

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .alerts import Alert, AlertManager, AlertSeverity


@dataclass
class FileChecksum:
    """Checksum record for a monitored file."""
    path: str
    sha256: str
    size: int
    modified_time: float
    checked_at: datetime = field(default_factory=datetime.now)


@dataclass
class IntegrityViolation:
    """Record of a file integrity violation."""
    path: str
    violation_type: str  # "modified", "deleted", "created"
    expected_hash: Optional[str]
    actual_hash: Optional[str]
    detected_at: datetime = field(default_factory=datetime.now)


class FileIntegrityMonitor:
    """Monitor critical agent files for unauthorized changes.

    This class implements file integrity monitoring (FIM) for OpenClaw
    agent configuration files. It detects modifications to files like
    SOUL.md that could indicate a prompt injection persistence attack.

    Reference:
    - ClawSec: https://github.com/prompt-security/clawsec
    - Penligent Research on SOUL.md attacks

    Attributes:
        config_dir: Directory containing agent configuration
        checksum_file: Path to store checksums
        monitored_files: List of files to monitor
        auto_restore: Whether to automatically restore modified files
    """

    # Default files to monitor
    # Reference: https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/
    DEFAULT_MONITORED_FILES = [
        "SOUL.md",
        "IDENTITY.md",
        "AGENTS.md",
        "SKILLS.md",
        "config.yaml",
        "config.yml",
        ".env",
    ]

    def __init__(
        self,
        config_dir: str,
        alert_manager: Optional[AlertManager] = None,
        monitored_files: Optional[List[str]] = None,
        auto_restore: bool = False,
        backup_dir: Optional[str] = None,
    ):
        """Initialize the file integrity monitor.

        Args:
            config_dir: Directory containing agent configuration files
            alert_manager: Optional AlertManager for sending alerts
            monitored_files: List of files to monitor (relative to config_dir)
            auto_restore: Whether to restore files from backup on violation
            backup_dir: Directory to store file backups
        """
        self.config_dir = Path(config_dir)
        self.alert_manager = alert_manager or AlertManager()
        self.monitored_files = monitored_files or self.DEFAULT_MONITORED_FILES
        self.auto_restore = auto_restore
        self.backup_dir = Path(backup_dir) if backup_dir else self.config_dir / ".security_backups"

        # Checksum storage
        self.checksum_file = self.config_dir / ".security_checksums.json"
        self.checksums: Dict[str, FileChecksum] = {}

        # Load existing checksums
        self._load_checksums()

    def _load_checksums(self) -> None:
        """Load checksums from storage file."""
        if self.checksum_file.exists():
            try:
                with open(self.checksum_file, 'r') as f:
                    data = json.load(f)
                    for path, info in data.items():
                        self.checksums[path] = FileChecksum(
                            path=path,
                            sha256=info['sha256'],
                            size=info['size'],
                            modified_time=info['modified_time'],
                            checked_at=datetime.fromisoformat(info['checked_at']),
                        )
            except (json.JSONDecodeError, KeyError):
                self.checksums = {}

    def _save_checksums(self) -> None:
        """Save checksums to storage file."""
        data = {}
        for path, checksum in self.checksums.items():
            data[path] = {
                'sha256': checksum.sha256,
                'size': checksum.size,
                'modified_time': checksum.modified_time,
                'checked_at': checksum.checked_at.isoformat(),
            }

        with open(self.checksum_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file.

        Reference: Industry standard for file integrity verification
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def initialize(self) -> Dict[str, FileChecksum]:
        """Initialize checksums for all monitored files.

        This should be called once during initial setup to establish
        the baseline for integrity monitoring.

        Returns:
            Dict of file paths to their checksums
        """
        for filename in self.monitored_files:
            file_path = self.config_dir / filename
            if file_path.exists():
                stat = file_path.stat()
                self.checksums[filename] = FileChecksum(
                    path=filename,
                    sha256=self._compute_hash(file_path),
                    size=stat.st_size,
                    modified_time=stat.st_mtime,
                )

                # Create backup if auto_restore is enabled
                if self.auto_restore:
                    self._create_backup(file_path)

        self._save_checksums()
        return self.checksums

    def _create_backup(self, file_path: Path) -> None:
        """Create backup of a file for potential restoration."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = self.backup_dir / file_path.name
        shutil.copy2(file_path, backup_path)

    def _restore_from_backup(self, filename: str) -> bool:
        """Restore a file from backup.

        Returns:
            True if restoration successful, False otherwise
        """
        backup_path = self.backup_dir / filename
        target_path = self.config_dir / filename

        if backup_path.exists():
            shutil.copy2(backup_path, target_path)
            return True
        return False

    def check(self) -> List[IntegrityViolation]:
        """Check all monitored files for integrity violations.

        Returns:
            List of detected violations
        """
        violations = []

        for filename in self.monitored_files:
            file_path = self.config_dir / filename

            # Check if file was deleted
            if filename in self.checksums and not file_path.exists():
                violation = IntegrityViolation(
                    path=filename,
                    violation_type="deleted",
                    expected_hash=self.checksums[filename].sha256,
                    actual_hash=None,
                )
                violations.append(violation)
                self._handle_violation(violation)
                continue

            # Check if file was created (not in baseline)
            if filename not in self.checksums and file_path.exists():
                violation = IntegrityViolation(
                    path=filename,
                    violation_type="created",
                    expected_hash=None,
                    actual_hash=self._compute_hash(file_path),
                )
                violations.append(violation)
                self._handle_violation(violation)
                continue

            # Check if file was modified
            if file_path.exists() and filename in self.checksums:
                current_hash = self._compute_hash(file_path)
                expected_hash = self.checksums[filename].sha256

                if current_hash != expected_hash:
                    violation = IntegrityViolation(
                        path=filename,
                        violation_type="modified",
                        expected_hash=expected_hash,
                        actual_hash=current_hash,
                    )
                    violations.append(violation)
                    self._handle_violation(violation)

        return violations

    def _handle_violation(self, violation: IntegrityViolation) -> None:
        """Handle a detected integrity violation.

        Reference: Detection signals from Penligent research
        """
        # Create alert
        alert = Alert(
            alert_type="integrity_violation",
            severity=AlertSeverity.CRITICAL,
            title=f"File Integrity Violation: {violation.path}",
            description=(
                f"File '{violation.path}' was {violation.violation_type}. "
                f"This may indicate a prompt injection persistence attack. "
                f"Expected hash: {violation.expected_hash or 'N/A'}, "
                f"Actual hash: {violation.actual_hash or 'N/A'}"
            ),
            metadata={
                "file": violation.path,
                "violation_type": violation.violation_type,
                "expected_hash": violation.expected_hash,
                "actual_hash": violation.actual_hash,
            },
            reference="https://www.penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem-persistence-tool-hijack-and-the-security-boundary-that-doesnt-exist/",
        )
        self.alert_manager.send(alert)

        # Auto-restore if enabled
        if self.auto_restore and violation.violation_type in ("modified", "deleted"):
            if self._restore_from_backup(violation.path):
                self.alert_manager.send(Alert(
                    alert_type="integrity_restored",
                    severity=AlertSeverity.INFO,
                    title=f"File Restored: {violation.path}",
                    description=f"File '{violation.path}' was automatically restored from backup.",
                ))

    def update_baseline(self, filename: str) -> Optional[FileChecksum]:
        """Update the baseline checksum for a file.

        Use this after legitimate file modifications.

        Args:
            filename: Name of the file to update

        Returns:
            New checksum or None if file doesn't exist
        """
        file_path = self.config_dir / filename

        if not file_path.exists():
            if filename in self.checksums:
                del self.checksums[filename]
            return None

        stat = file_path.stat()
        checksum = FileChecksum(
            path=filename,
            sha256=self._compute_hash(file_path),
            size=stat.st_size,
            modified_time=stat.st_mtime,
        )
        self.checksums[filename] = checksum

        if self.auto_restore:
            self._create_backup(file_path)

        self._save_checksums()
        return checksum

    def get_status(self) -> Dict:
        """Get current monitoring status.

        Returns:
            Dict with status information
        """
        return {
            "config_dir": str(self.config_dir),
            "monitored_files": self.monitored_files,
            "tracked_files": list(self.checksums.keys()),
            "auto_restore": self.auto_restore,
            "last_check": max(
                (c.checked_at for c in self.checksums.values()),
                default=None
            ),
        }
