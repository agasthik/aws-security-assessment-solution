#!/usr/bin/env python3
"""
Analytics Module - Security analytics and insights generation.
"""

import pandas as pd
import logging
from typing import Dict, List, Tuple, Any
from collections import Counter

logger = logging.getLogger(__name__)


class SecurityAnalytics:
    """Generates security analytics and insights from findings data."""

    def __init__(self):
        """Initialize the analytics engine."""
        self.severity_order = ["Critical", "High", "Medium", "Low", "Info"]

    def generate_summary_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate summary statistics for the dashboard.

        Args:
            df: Processed security findings DataFrame

        Returns:
            Dictionary with summary statistics
        """
        if df.empty:
            return self._empty_summary()

        logger.info("Generating summary statistics")

        # Basic counts
        total_findings = len(df)
        unique_accounts = (
            df["ACCOUNT_UID"].nunique() if "ACCOUNT_UID" in df.columns else 0
        )
        unique_services = (
            df["SERVICE_NAME"].nunique() if "SERVICE_NAME" in df.columns else 0
        )
        unique_regions = df["REGION"].nunique() if "REGION" in df.columns else 0

        # Severity breakdown
        severity_counts = {}
        if "SEVERITY" in df.columns:
            severity_counts = df["SEVERITY"].value_counts().to_dict()

        # Status breakdown
        status_counts = {}
        if "STATUS" in df.columns:
            status_counts = df["STATUS"].value_counts().to_dict()

        # Failed findings by severity
        failed_by_severity = {}
        if "STATUS" in df.columns and "SEVERITY" in df.columns:
            failed_df = df[df["STATUS"] == "Failed"]
            failed_by_severity = failed_df["SEVERITY"].value_counts().to_dict()

        return {
            "total_findings": total_findings,
            "unique_accounts": unique_accounts,
            "unique_services": unique_services,
            "unique_regions": unique_regions,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "failed_by_severity": failed_by_severity,
            "critical_findings": failed_by_severity.get("Critical", 0),
            "high_findings": failed_by_severity.get("High", 0),
            "medium_findings": failed_by_severity.get("Medium", 0),
            "low_findings": failed_by_severity.get("Low", 0),
        }

    def analyze_top_failing_checks(
        self, df: pd.DataFrame, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Analyze the most frequently failing security checks.

        Args:
            df: Security findings DataFrame
            limit: Number of top checks to return

        Returns:
            List of top failing checks with details
        """
        if df.empty or "STATUS" not in df.columns:
            return []

        failed_df = df[df["STATUS"] == "Failed"]
        if failed_df.empty:
            return []

        # Group by check and count failures
        check_failures = (
            failed_df.groupby(["CHECK_ID", "CHECK_TITLE"])
            .agg(
                {
                    "FINDING_UID": "count",
                    "SEVERITY": lambda x: (
                        x.mode().iloc[0] if not x.empty else "Unknown"
                    ),
                    "SERVICE_NAME": lambda x: (
                        x.mode().iloc[0] if not x.empty else "Unknown"
                    ),
                }
            )
            .reset_index()
        )

        check_failures.columns = [
            "check_id",
            "check_title",
            "failure_count",
            "severity",
            "service",
        ]
        check_failures = check_failures.sort_values(
            "failure_count", ascending=False
        ).head(limit)

        return check_failures.to_dict("records")

    def analyze_account_security_posture(
        self, df: pd.DataFrame
    ) -> List[Dict[str, Any]]:
        """Analyze security posture by account.

        Args:
            df: Security findings DataFrame

        Returns:
            List of account security analysis
        """
        if df.empty or "ACCOUNT_UID" not in df.columns:
            return []

        account_analysis = []

        for account in df["ACCOUNT_UID"].unique():
            account_df = df[df["ACCOUNT_UID"] == account]

            total_findings = len(account_df)
            failed_findings = (
                len(account_df[account_df["STATUS"] == "Failed"])
                if "STATUS" in account_df.columns
                else 0
            )

            # Severity breakdown for failed findings
            failed_by_severity = {}
            if "STATUS" in account_df.columns and "SEVERITY" in account_df.columns:
                failed_df = account_df[account_df["STATUS"] == "Failed"]
                failed_by_severity = failed_df["SEVERITY"].value_counts().to_dict()

            # Calculate risk score
            risk_score = self._calculate_risk_score(failed_by_severity)

            account_name = (
                account_df["ACCOUNT_NAME"].iloc[0]
                if "ACCOUNT_NAME" in account_df.columns
                else str(account)
            )

            account_analysis.append(
                {
                    "account_id": account,
                    "account_name": account_name,
                    "total_findings": total_findings,
                    "failed_findings": failed_findings,
                    "pass_rate": round(
                        (total_findings - failed_findings) / total_findings * 100, 1
                    )
                    if total_findings > 0
                    else 100,
                    "critical_failures": failed_by_severity.get("Critical", 0),
                    "high_failures": failed_by_severity.get("High", 0),
                    "medium_failures": failed_by_severity.get("Medium", 0),
                    "low_failures": failed_by_severity.get("Low", 0),
                    "risk_score": risk_score,
                }
            )

        # Sort by risk score (highest first)
        account_analysis.sort(key=lambda x: x["risk_score"], reverse=True)
        return account_analysis

    def analyze_service_vulnerabilities(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities by cloud service.

        Args:
            df: Security findings DataFrame

        Returns:
            List of service vulnerability analysis
        """
        if df.empty or "SERVICE_NAME" not in df.columns:
            return []

        service_analysis = []

        for service in df["SERVICE_NAME"].unique():
            service_df = df[df["SERVICE_NAME"] == service]

            total_findings = len(service_df)
            failed_findings = (
                len(service_df[service_df["STATUS"] == "Failed"])
                if "STATUS" in service_df.columns
                else 0
            )

            # Severity breakdown for failed findings
            failed_by_severity = {}
            if "STATUS" in service_df.columns and "SEVERITY" in service_df.columns:
                failed_df = service_df[service_df["STATUS"] == "Failed"]
                failed_by_severity = failed_df["SEVERITY"].value_counts().to_dict()

            # Calculate risk score
            risk_score = self._calculate_risk_score(failed_by_severity)

            service_analysis.append(
                {
                    "service_name": service,
                    "total_findings": total_findings,
                    "failed_findings": failed_findings,
                    "failure_rate": round(failed_findings / total_findings * 100, 1)
                    if total_findings > 0
                    else 0,
                    "critical_failures": failed_by_severity.get("Critical", 0),
                    "high_failures": failed_by_severity.get("High", 0),
                    "medium_failures": failed_by_severity.get("Medium", 0),
                    "low_failures": failed_by_severity.get("Low", 0),
                    "risk_score": risk_score,
                }
            )

        # Sort by critical failures (highest first), then by high failures, then by risk score
        service_analysis.sort(
            key=lambda x: (x["critical_failures"], x["high_failures"], x["risk_score"]),
            reverse=True,
        )
        return service_analysis

    def analyze_compliance_gaps(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze compliance framework gaps with severity breakdown.

        Args:
            df: Security findings DataFrame

        Returns:
            Compliance analysis results with severity details
        """
        if df.empty or "COMPLIANCE_FRAMEWORKS" not in df.columns:
            return {"frameworks": [], "total_violations": 0}

        # Get failed findings with compliance info
        failed_df = df[df["STATUS"] == "Failed"] if "STATUS" in df.columns else df

        # Parse compliance frameworks and track severity
        framework_severity_data = {}

        for _, row in failed_df.iterrows():
            frameworks_str = row.get("COMPLIANCE_FRAMEWORKS", "")
            severity = row.get("SEVERITY", "Unknown")

            if frameworks_str and frameworks_str != "":
                frameworks = [f.strip() for f in frameworks_str.split(",")]
                for framework in frameworks:
                    if framework and framework != "Other":
                        if framework not in framework_severity_data:
                            framework_severity_data[framework] = {
                                "Critical": 0,
                                "High": 0,
                                "Medium": 0,
                                "Low": 0,
                                "Info": 0,
                            }
                        framework_severity_data[framework][severity] = (
                            framework_severity_data[framework].get(severity, 0) + 1
                        )

        compliance_analysis = []
        for framework, severity_counts in framework_severity_data.items():
            total_violations = sum(severity_counts.values())
            risk_score = self._calculate_risk_score(severity_counts)

            compliance_analysis.append(
                {
                    "framework": framework,
                    "violations": total_violations,
                    "critical_violations": severity_counts.get("Critical", 0),
                    "high_violations": severity_counts.get("High", 0),
                    "medium_violations": severity_counts.get("Medium", 0),
                    "low_violations": severity_counts.get("Low", 0),
                    "info_violations": severity_counts.get("Info", 0),
                    "risk_score": risk_score,
                    "percentage": round(total_violations / len(failed_df) * 100, 1)
                    if len(failed_df) > 0
                    else 0,
                }
            )

        # Sort by risk score (highest first), then by total violations
        compliance_analysis.sort(
            key=lambda x: (x["risk_score"], x["violations"]), reverse=True
        )

        return {"frameworks": compliance_analysis, "total_violations": len(failed_df)}

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate risk score based on severity distribution.

        Args:
            severity_counts: Dictionary of severity counts

        Returns:
            Risk score (0-100)
        """
        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 1}

        total_weighted = sum(
            severity_counts.get(severity, 0) * weight
            for severity, weight in weights.items()
        )
        total_findings = sum(severity_counts.values())

        if total_findings == 0:
            return 0.0

        # Normalize to 0-100 scale
        max_possible = total_findings * weights["Critical"]
        risk_score = (total_weighted / max_possible * 100) if max_possible > 0 else 0

        return round(risk_score, 1)

    def _empty_summary(self) -> Dict[str, Any]:
        """Return empty summary statistics."""
        return {
            "total_findings": 0,
            "unique_accounts": 0,
            "unique_services": 0,
            "unique_regions": 0,
            "severity_counts": {},
            "status_counts": {},
            "failed_by_severity": {},
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
        }

    def calculate_summary_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate comprehensive summary statistics."""
        return self.generate_summary_stats(df)

    def analyze_trends_by_account(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze security trends by account."""
        if df.empty or "ACCOUNT_UID" not in df.columns:
            return []

        account_stats = []
        for account in df["ACCOUNT_UID"].unique():
            account_data = df[df["ACCOUNT_UID"] == account]
            stats = {
                "account_id": account,
                "total_findings": len(account_data),
                "failed_findings": len(account_data[account_data["STATUS"] == "Failed"])
                if "STATUS" in df.columns
                else 0,
                "critical_findings": len(
                    account_data[account_data["SEVERITY"] == "Critical"]
                )
                if "SEVERITY" in df.columns
                else 0,
            }
            account_stats.append(stats)

        return sorted(account_stats, key=lambda x: x["failed_findings"], reverse=True)

    def identify_top_failing_services(
        self, df: pd.DataFrame, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Identify services with most failures."""
        if df.empty or "SERVICE_NAME" not in df.columns:
            return []

        failed_df = df[df["STATUS"] == "Failed"] if "STATUS" in df.columns else df
        service_counts = failed_df["SERVICE_NAME"].value_counts().head(limit)

        return [
            {"service": service, "failure_count": count}
            for service, count in service_counts.items()
        ]

    def assess_compliance_framework_violations(
        self, df: pd.DataFrame
    ) -> Dict[str, Any]:
        """Assess compliance framework violations."""
        if df.empty:
            return {"total_violations": 0, "compliance_rate": 100.0}

        total_checks = len(df)
        failed_checks = (
            len(df[df["STATUS"] == "Failed"]) if "STATUS" in df.columns else 0
        )
        compliance_rate = (
            ((total_checks - failed_checks) / total_checks * 100)
            if total_checks > 0
            else 100.0
        )

        return {
            "total_violations": failed_checks,
            "compliance_rate": compliance_rate,
            "total_checks": total_checks,
        }

    def analyze_regional_distribution(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze regional distribution of findings with detailed breakdown.

        Args:
            df: Security findings DataFrame

        Returns:
            List of regional analysis data
        """
        if df.empty or "REGION" not in df.columns:
            return []

        regional_analysis = []

        for region in df["REGION"].unique():
            if pd.isna(region) or region == "Unknown Region":
                continue

            region_df = df[df["REGION"] == region]

            total_findings = len(region_df)
            failed_findings = (
                len(region_df[region_df["STATUS"] == "Failed"])
                if "STATUS" in region_df.columns
                else 0
            )

            # Severity breakdown for failed findings
            failed_by_severity = {}
            if "STATUS" in region_df.columns and "SEVERITY" in region_df.columns:
                failed_df = region_df[region_df["STATUS"] == "Failed"]
                failed_by_severity = failed_df["SEVERITY"].value_counts().to_dict()

            # Calculate risk score
            risk_score = self._calculate_risk_score(failed_by_severity)

            # Count unique accounts in this region
            unique_accounts = (
                region_df["ACCOUNT_UID"].nunique()
                if "ACCOUNT_UID" in region_df.columns
                else 0
            )

            regional_analysis.append(
                {
                    "region": region,
                    "total_findings": total_findings,
                    "failed_findings": failed_findings,
                    "pass_rate": round(
                        (total_findings - failed_findings) / total_findings * 100, 1
                    )
                    if total_findings > 0
                    else 100,
                    "critical_failures": failed_by_severity.get("Critical", 0),
                    "high_failures": failed_by_severity.get("High", 0),
                    "medium_failures": failed_by_severity.get("Medium", 0),
                    "low_failures": failed_by_severity.get("Low", 0),
                    "risk_score": risk_score,
                    "unique_accounts": unique_accounts,
                }
            )

        # Sort by total findings (highest first)
        regional_analysis.sort(key=lambda x: x["total_findings"], reverse=True)
        return regional_analysis

    # DISABLED: Heat map functionality temporarily disabled
    # def analyze_risk_heat_map(self, df: pd.DataFrame) -> Dict[str, Any]:
    #     """Analyze risk heat map data by service and account.
    #
    #     Args:
    #         df: Security findings DataFrame
    #
    #     Returns:
    #         Heat map data with services, accounts, and risk matrix
    #     """
    #     if df.empty or 'SERVICE_NAME' not in df.columns or 'ACCOUNT_UID' not in df.columns:
    #         return {'services': [], 'accounts': [], 'risk_matrix': [], 'max_risk': 0}
    #
    #     # Get unique services and accounts
    #     services = sorted(df['SERVICE_NAME'].unique())
    #     accounts = sorted(df['ACCOUNT_UID'].unique())
    #
    #     # Create risk matrix
    #     risk_matrix = []
    #     max_risk = 0
    #
    #     for service in services:
    #         service_row = []
    #         for account in accounts:
    #             # Filter data for this service-account combination
    #             subset = df[(df['SERVICE_NAME'] == service) & (df['ACCOUNT_UID'] == account)]
    #
    #             if subset.empty:
    #                 risk_score = 0
    #                 finding_count = 0
    #             else:
    #                 # Calculate risk for this combination
    #                 failed_subset = subset[subset['STATUS'] == 'Failed'] if 'STATUS' in subset.columns else subset
    #
    #                 if failed_subset.empty:
    #                     risk_score = 0
    #                     finding_count = 0
    #                 else:
    #                     # Severity breakdown for failed findings
    #                     failed_by_severity = {}
    #                     if 'SEVERITY' in failed_subset.columns:
    #                         failed_by_severity = failed_subset['SEVERITY'].value_counts().to_dict()
    #
    #                     risk_score = self._calculate_risk_score(failed_by_severity)
    #                     finding_count = len(failed_subset)
    #
    #             service_row.append({
    #                 'service': service,
    #                 'account': account,
    #                 'risk_score': risk_score,
    #                 'finding_count': finding_count,
    #                 'total_findings': len(subset)
    #             })
    #
    #             max_risk = max(max_risk, risk_score)
    #
    #         risk_matrix.append(service_row)
    #
    #     # Get account names for display
    #     account_names = []
    #     for account in accounts:
    #         account_data = df[df['ACCOUNT_UID'] == account]
    #         account_name = account_data['ACCOUNT_NAME'].iloc[0] if 'ACCOUNT_NAME' in account_data.columns and not account_data.empty else str(account)
    #         account_names.append({
    #             'id': account,
    #             'name': account_name[:20] + '...' if len(account_name) > 20 else account_name  # Truncate long names
    #         })
    #
    #     return {
    #         'services': services,
    #         'accounts': account_names,
    #         'risk_matrix': risk_matrix,
    #         'max_risk': max_risk
    #     }

    def analyze_security_posture_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze security posture trends."""
        if df.empty:
            return {"trend": "stable", "score": 0}

        total_findings = len(df)
        failed_findings = (
            len(df[df["STATUS"] == "Failed"]) if "STATUS" in df.columns else 0
        )
        score = (
            ((total_findings - failed_findings) / total_findings * 100)
            if total_findings > 0
            else 100
        )

        return {
            "trend": "improving" if score > 70 else "needs_attention",
            "score": score,
        }

    def analyze_improvement_roadmap(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze findings and create improvement roadmap with immediate, short-term, and long-term fixes.

        Args:
            df: Security findings DataFrame

        Returns:
            Dictionary containing roadmap with categorized fixes
        """
        if df.empty:
            return {
                "immediate": {"count": 0, "items": [], "effort_weeks": 0},
                "short_term": {"count": 0, "items": [], "effort_weeks": 0},
                "long_term": {"count": 0, "items": [], "effort_weeks": 0},
                "summary": {"total_issues": 0, "total_effort_weeks": 0},
            }

        # Filter to failed findings only
        failed_df = df[df["STATUS"] == "Failed"] if "STATUS" in df.columns else df

        if failed_df.empty:
            return {
                "immediate": {"count": 0, "items": [], "effort_weeks": 0},
                "short_term": {"count": 0, "items": [], "effort_weeks": 0},
                "long_term": {"count": 0, "items": [], "effort_weeks": 0},
                "summary": {"total_issues": 0, "total_effort_weeks": 0},
            }

        # Initialize roadmap categories
        immediate_fixes = []
        short_term_fixes = []
        long_term_fixes = []

        # Define fix complexity mapping based on check types and services
        quick_fix_patterns = [
            "encryption",
            "ssl",
            "tls",
            "certificate",
            "password",
            "mfa",
            "public",
            "open",
            "logging",
            "monitoring",
            "backup",
            "versioning",
            "lifecycle",
        ]

        complex_fix_patterns = [
            "vpc",
            "network",
            "architecture",
            "compliance",
            "governance",
            "policy",
            "infrastructure",
            "configuration",
            "integration",
        ]

        # Group findings by check for better analysis
        if "CHECK_ID" in failed_df.columns and "CHECK_TITLE" in failed_df.columns:
            check_groups = (
                failed_df.groupby(["CHECK_ID", "CHECK_TITLE"])
                .agg(
                    {
                        "SEVERITY": "first",
                        "SERVICE_NAME": "first",
                        "ACCOUNT_UID": "count",  # Count of affected resources
                    }
                )
                .reset_index()
            )
            check_groups.rename(
                columns={"ACCOUNT_UID": "affected_resources"}, inplace=True
            )
        else:
            # Fallback if columns don't exist
            check_groups = pd.DataFrame(
                {
                    "CHECK_ID": ["UNKNOWN"],
                    "CHECK_TITLE": ["Security Issues Found"],
                    "SEVERITY": ["Medium"],
                    "SERVICE_NAME": ["Multiple"],
                    "affected_resources": [len(failed_df)],
                }
            )

        for _, check in check_groups.iterrows():
            severity = check.get("SEVERITY", "Medium")
            title = check.get("CHECK_TITLE", "Unknown Check")
            service = check.get("SERVICE_NAME", "Unknown")
            resources = check.get("affected_resources", 1)
            check_id = check.get("CHECK_ID", "UNKNOWN")

            # Determine fix complexity based on title and service
            title_lower = title.lower()
            service_lower = service.lower()

            is_quick_fix = any(pattern in title_lower for pattern in quick_fix_patterns)
            is_complex_fix = any(
                pattern in title_lower for pattern in complex_fix_patterns
            )

            # Estimate effort (in person-days, converted to weeks)
            if is_quick_fix:
                effort_days = min(2, max(1, resources * 0.5))  # 0.5-2 days per resource
            elif is_complex_fix:
                effort_days = min(20, max(5, resources * 2))  # 2-20 days per resource
            else:
                effort_days = min(10, max(2, resources * 1))  # 1-10 days per resource

            effort_weeks = round(effort_days / 5, 1)  # Convert to weeks

            fix_item = {
                "title": title,
                "service": service,
                "severity": severity,
                "affected_resources": resources,
                "effort_weeks": effort_weeks,
                "check_id": check_id,
                "description": self._generate_fix_description(
                    title, service, resources
                ),
            }

            # Categorize based on severity and complexity
            if severity == "Critical":
                immediate_fixes.append(fix_item)
            elif severity == "High":
                if is_quick_fix:
                    immediate_fixes.append(fix_item)
                else:
                    short_term_fixes.append(fix_item)
            elif severity == "Medium":
                if is_quick_fix:
                    short_term_fixes.append(fix_item)
                else:
                    long_term_fixes.append(fix_item)
            else:  # Low severity
                long_term_fixes.append(fix_item)

        # Sort each category by severity priority and effort
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

        for fixes_list in [immediate_fixes, short_term_fixes, long_term_fixes]:
            fixes_list.sort(
                key=lambda x: (
                    severity_order.get(x["severity"], 5),
                    -x[
                        "affected_resources"
                    ],  # More affected resources = higher priority
                    x["effort_weeks"],  # Less effort = higher priority
                )
            )

        # Calculate totals
        immediate_effort = sum(item["effort_weeks"] for item in immediate_fixes)
        short_term_effort = sum(item["effort_weeks"] for item in short_term_fixes)
        long_term_effort = sum(item["effort_weeks"] for item in long_term_fixes)

        return {
            "immediate": {
                "count": len(immediate_fixes),
                "items": immediate_fixes[:10],  # Limit to top 10 for display
                "effort_weeks": round(immediate_effort, 1),
                "timeline": "1-2 weeks",
                "description": "Critical and high-severity issues requiring immediate attention",
            },
            "short_term": {
                "count": len(short_term_fixes),
                "items": short_term_fixes[:10],  # Limit to top 10 for display
                "effort_weeks": round(short_term_effort, 1),
                "timeline": "1-2 months",
                "description": "Important security improvements with moderate complexity",
            },
            "long_term": {
                "count": len(long_term_fixes),
                "items": long_term_fixes[:10],  # Limit to top 10 for display
                "effort_weeks": round(long_term_effort, 1),
                "timeline": "3-6 months",
                "description": "Strategic security enhancements and architectural improvements",
            },
            "summary": {
                "total_issues": len(immediate_fixes)
                + len(short_term_fixes)
                + len(long_term_fixes),
                "total_effort_weeks": round(
                    immediate_effort + short_term_effort + long_term_effort, 1
                ),
                "critical_count": len(
                    [f for f in immediate_fixes if f["severity"] == "Critical"]
                ),
                "high_count": len(
                    [
                        f
                        for f in immediate_fixes + short_term_fixes
                        if f["severity"] == "High"
                    ]
                ),
            },
        }

    def _generate_fix_description(
        self, title: str, service: str, resources: int
    ) -> str:
        """Generate a concise fix description based on the check title and service."""
        title_lower = title.lower()

        # Common fix descriptions based on patterns
        if "encryption" in title_lower:
            return f"Enable encryption for {resources} {service} resource(s)"
        elif "public" in title_lower or "open" in title_lower:
            return f"Restrict public access for {resources} {service} resource(s)"
        elif "mfa" in title_lower:
            return f"Enable MFA for {resources} account(s)/user(s)"
        elif "logging" in title_lower:
            return f"Enable logging for {resources} {service} resource(s)"
        elif "backup" in title_lower:
            return f"Configure backups for {resources} {service} resource(s)"
        elif (
            "certificate" in title_lower or "ssl" in title_lower or "tls" in title_lower
        ):
            return f"Update SSL/TLS certificates for {resources} {service} resource(s)"
        elif "password" in title_lower:
            return f"Update password policies for {resources} resource(s)"
        elif "versioning" in title_lower:
            return f"Enable versioning for {resources} {service} resource(s)"
        elif "monitoring" in title_lower:
            return f"Configure monitoring for {resources} {service} resource(s)"
        else:
            return (
                f"Address security configuration for {resources} {service} resource(s)"
            )

    def generate_remediation_recommendations(
        self, df: pd.DataFrame
    ) -> List[Dict[str, Any]]:
        """Generate remediation recommendations."""
        if df.empty:
            return []

        recommendations = []
        if "SERVICE_NAME" in df.columns:
            top_services = self.identify_top_failing_services(df, 3)
            for service in top_services:
                recommendations.append(
                    {
                        "priority": "high",
                        "service": service["service"],
                        "recommendation": f"Review and remediate {service['failure_count']} findings in {service['service']}",
                    }
                )

        return recommendations

    def _calculate_weighted_risk_score(self, df: pd.DataFrame) -> float:
        """Calculate weighted risk score based on DataFrame."""
        if df.empty:
            return 0.0

        severity_weights = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0.5,
        }
        total_score = 0

        for _, row in df.iterrows():
            if "SEVERITY" in row and "STATUS" in row:
                weight = severity_weights.get(row["SEVERITY"], 1)
                if row["STATUS"] == "Failed":
                    total_score += weight

        return total_score / len(df) if len(df) > 0 else 0.0

    def _empty_summary_stats(self) -> Dict[str, Any]:
        """Return empty summary stats structure."""
        return self._empty_summary()

    @property
    def severity_weights(self) -> Dict[str, float]:
        """Severity weights for risk calculation."""
        return {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}

    @property
    def status_weights(self) -> Dict[str, float]:
        """Status weights for risk calculation."""
        return {"FAIL": 1.0, "PASS": 0.0, "MANUAL": 0.5, "INFO": 0.1}
