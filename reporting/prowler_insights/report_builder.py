#!/usr/bin/env python3
"""
Report Builder Module - HTML dashboard builder for security insights.
"""

import html
import json
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Builds HTML dashboard reports from security analysis data."""

    # Provider display metadata: label, icon class, CSS color
    PROVIDER_META = {
        "aws": {"label": "AWS", "icon": "fab fa-aws", "color": "#FF9900"},
        "azure": {"label": "Azure", "icon": "fab fa-microsoft", "color": "#0078D4"},
        "gcp": {"label": "GCP", "icon": "fab fa-google", "color": "#4285F4"},
    }

    def __init__(self):
        """Initialize the report builder."""
        self.template_css = self._get_css_styles()
        self.template_js = self._get_javascript_code()

    @staticmethod
    def _esc(value) -> str:
        """HTML-escape a value for safe embedding in HTML content and attributes."""
        if value is None:
            return ""
        return html.escape(str(value), quote=True)

    def _provider_label(self, providers: list) -> str:
        """Return a human-readable label for the detected providers."""
        if not providers:
            return "Cloud"
        labels = [
            self.PROVIDER_META.get(p, {}).get("label", p.upper()) for p in providers
        ]
        return " + ".join(labels)

    def _provider_account_noun(self, providers: list) -> str:
        """Return the correct noun for accounts/subscriptions/projects."""
        nouns = {
            "aws": "Accounts",
            "azure": "Subscriptions",
            "gcp": "Projects",
        }
        if not providers or len(providers) > 1:
            return "Accounts"
        return nouns.get(providers[0], "Accounts")

    def _provider_region_noun(self, providers: list) -> str:
        """Return the correct noun for regions/locations."""
        nouns = {
            "aws": "Regions",
            "azure": "Regions",
            "gcp": "Regions",
        }
        if not providers:
            return "Regions"
        return nouns.get(providers[0], "Regions")

    def _provider_badges_html(self, providers: list) -> str:
        """Return small HTML badges for each detected provider."""
        if not providers:
            return ""
        badges = []
        for p in providers:
            meta = self.PROVIDER_META.get(
                p, {"label": p.upper(), "icon": "fas fa-cloud", "color": "#6c757d"}
            )
            label = self._esc(meta["label"])
            icon = self._esc(meta["icon"])
            color = self._esc(meta["color"])
            badges.append(
                f'<span class="badge" style="background-color:{color};color:#fff;margin-right:4px;">'
                f'<i class="{icon}"></i> {label}</span>'
            )
        return " ".join(badges)

    def build_dashboard(
        self,
        summary_stats: Dict[str, Any],
        account_analysis: List[Dict[str, Any]],
        service_analysis: List[Dict[str, Any]],
        compliance_analysis: Dict[str, Any],
        top_checks: List[Dict[str, Any]],
        chart_configs: Dict[str, str],
        company_name: str = None,
        raw_data: List[Dict[str, Any]] = None,
        regional_analysis: List[Dict[str, Any]] = None,
        heat_map_data: Dict[str, Any] = None,
        roadmap_data: Dict[str, Any] = None,
    ) -> str:
        """Build complete HTML dashboard.

        Args:
            summary_stats: Summary statistics
            account_analysis: Account security analysis
            service_analysis: Service vulnerability analysis
            compliance_analysis: Compliance framework analysis
            top_checks: Top failing security checks
            chart_configs: Chart.js configurations
            company_name: Optional company name to display in header
            raw_data: Raw data (deprecated, kept for compatibility)
            regional_analysis: Regional distribution analysis
            heat_map_data: Risk heat map analysis data
            roadmap_data: Improvement roadmap analysis data

        Returns:
            Complete HTML dashboard as string
        """
        logger.info("Building HTML dashboard")

        # Build page title with optional company name
        page_title = (
            f"CSPM Security Insights Dashboard for {self._esc(company_name)}"
            if company_name
            else "CSPM Security Insights Dashboard"
        )

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {self.template_css}
    </style>
</head>
<body>
    {self._build_navigation_menu()}

    <div class="main-content">
        <div class="container-fluid">
            {self._build_header(summary_stats, company_name)}
            {self._build_filter_section()}
            {self._build_summary_cards(summary_stats)}
            {self._build_charts_section(chart_configs)}
            {self._build_regions_widget(regional_analysis, chart_configs)}
            {self._build_detailed_tables(account_analysis, service_analysis, top_checks)}
            {self._build_compliance_section(compliance_analysis)}
            {self._build_insights_section(summary_stats, account_analysis, service_analysis)}
            {self._build_roadmap_widget(roadmap_data, chart_configs)}
            {self._build_score_calculation_section()}
        </div>
    </div>

    <script>
        // Dashboard functionality

        {self.template_js}

        // Initialize charts
        {self._build_chart_initialization(chart_configs)}
    </script>
</body>
</html>
        """

        logger.info("HTML dashboard built successfully")
        return html_content

    def _build_navigation_menu(self) -> str:
        """Build collapsible navigation menu."""
        return """
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
            <div class="container-fluid">
                <button class="btn btn-outline-light btn-sm me-3" onclick="toggleSidebar()">
                    <i class="fas fa-bars"></i> Menu
                </button>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav me-auto">
                        <li class="nav-item">
                            <a class="nav-link" href="#overview">📊 Overview</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#charts">📈 Charts</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#regions">🌍 Regions</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#details">📋 Details</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#compliance">✅ Compliance</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#insights">💡 Insights</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#roadmap">🛣️ Roadmap</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#methodology">🔢 Methodology</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>

        <!-- Collapsible Sidebar -->
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <h5>Navigation</h5>
                <button class="btn btn-sm btn-outline-secondary" onclick="toggleSidebar()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="sidebar-content">
                <div class="nav-section">
                    <h6>📊 Dashboard Sections</h6>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link" href="#overview" onclick="scrollToSection('overview')">
                                <i class="fas fa-tachometer-alt"></i> Overview & Summary
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#charts" onclick="scrollToSection('charts')">
                                <i class="fas fa-chart-pie"></i> Security Charts
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#regions" onclick="scrollToSection('regions')">
                                <i class="fas fa-globe"></i> Regional Analysis
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#details" onclick="scrollToSection('details')">
                                <i class="fas fa-table"></i> Detailed Analysis
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#compliance" onclick="scrollToSection('compliance')">
                                <i class="fas fa-check-circle"></i> Compliance Status
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#insights" onclick="scrollToSection('insights')">
                                <i class="fas fa-lightbulb"></i> Key Insights
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#roadmap" onclick="scrollToSection('roadmap')">
                                <i class="fas fa-road"></i> Improvement Roadmap
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#methodology" onclick="scrollToSection('methodology')">
                                <i class="fas fa-calculator"></i> Score Methodology
                            </a>
                        </li>
                    </ul>
                </div>


            </div>
        </div>

        <!-- Sidebar Overlay -->
        <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
        """

    def _build_header(
        self, summary_stats: Dict[str, Any], company_name: str = None
    ) -> str:
        """Build dashboard header section."""
        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        overall_score = summary_stats.get("overall_score", 0)
        providers = summary_stats.get("providers", ["aws"])
        provider_label = self._provider_label(providers)
        account_noun = self._provider_account_noun(providers)
        provider_badges = self._provider_badges_html(providers)

        # Build title with optional company name
        if company_name:
            escaped_name = self._esc(company_name)
            title = f"CSPM Security Insights Dashboard for {escaped_name}"
            subtitle = (
                f"Security Insights from Prowler Scans for {escaped_name} across "
                f"{summary_stats.get('unique_accounts', 0)} {provider_label} {account_noun.lower()}"
            )
        else:
            title = "CSPM Security Insights Dashboard"
            subtitle = (
                f"Security Insights from Prowler Scans across "
                f"{summary_stats.get('unique_accounts', 0)} {provider_label} {account_noun.lower()}"
            )

        return f"""
        <div class="row mb-4" id="overview">
            <div class="col-12">
                <div class="dashboard-header">
                    <h1 class="display-4">{title}</h1>
                    <p class="lead">{subtitle} {provider_badges}</p>
                    <div class="d-flex justify-content-between align-items-center flex-wrap">
                        <span class="generation-time">Generated: {generation_time}</span>
                        <div class="security-score d-flex align-items-center">
                            <span class="score-label">Overall Security Score:</span>
                            <span class="score-value score-{self._get_score_class(overall_score)}">{overall_score}%</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_summary_cards(self, summary_stats: Dict[str, Any]) -> str:
        """Build summary statistics cards."""
        providers = summary_stats.get("providers", ["aws"])
        account_noun = self._provider_account_noun(providers)
        return f"""
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card summary-card">
                    <div class="card-body text-center">
                        <h3 class="card-title text-danger" id="criticalCount">{summary_stats.get("critical_findings", 0)}</h3>
                        <p class="card-text">Critical Findings</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card summary-card">
                    <div class="card-body text-center">
                        <h3 class="card-title text-warning" id="highCount">{summary_stats.get("high_findings", 0)}</h3>
                        <p class="card-text">High Findings</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card summary-card">
                    <div class="card-body text-center">
                        <h3 class="card-title text-info" id="totalCount">{summary_stats.get("total_findings", 0)}</h3>
                        <p class="card-text" id="totalLabel">Total Findings</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card summary-card">
                    <div class="card-body text-center">
                        <h3 class="card-title text-success" id="accountCount">{summary_stats.get("unique_accounts", 0)}</h3>
                        <p class="card-text">{account_noun}</p>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_filter_section(self) -> str:
        """Build global filter section."""
        return f"""
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>🔍 Global Filter</h5>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-4">
                                <label for="statusFilter" class="form-label">Filter by Finding Status:</label>
                                <select id="statusFilter" class="form-select" onchange="applyStatusFilter()">
                                    <option value="all">All Findings</option>
                                    <option value="Failed">Failed Only</option>
                                    <option value="Passed">Passed Only</option>
                                    <option value="Manual">Manual Only</option>
                                </select>
                            </div>
                            <div class="col-md-8">
                                <div class="alert alert-info mb-0" id="filterInfo">
                                    <small><strong>Current View:</strong> Showing all findings across all statuses</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_charts_section(self, chart_configs: Dict[str, str]) -> str:
        """Build charts section."""
        return f"""
        <div class="row mb-4" id="charts">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Severity Distribution</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="severityChart" height="300"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Account Security Comparison</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="accountChart" height="300"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Service Risk Analysis</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="serviceChart" height="300"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Top Failing Checks (by Failure Count)</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="checksChart" height="400"></canvas>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_regions_widget(
        self, regional_analysis: List[Dict[str, Any]], chart_configs: Dict[str, str]
    ) -> str:
        """Build regions distribution widget."""
        if not regional_analysis:
            return ""

        return f"""
        <div class="row mb-4" id="regions">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>🌍 Regional Distribution of Findings</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8">
                                <canvas id="regionsChart" height="300"></canvas>
                            </div>
                            <div class="col-md-4">
                                <h6>Top Regions by Findings</h6>
                                <div class="table-responsive">
                                    {self._build_regions_summary_table(regional_analysis[:5])}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_regions_summary_table(self, top_regions: List[Dict[str, Any]]) -> str:
        """Build regions summary table with severity breakdown."""
        if not top_regions:
            return "<p>No regional data available.</p>"

        rows = ""
        for region in top_regions:
            risk_class = self._get_risk_class(region["risk_score"])
            region_name = self._esc(region["region"])
            rows += f"""
            <tr>
                <td><small><strong>{region_name}</strong></small></td>
                <td class="text-center"><small>{region["total_findings"]}</small></td>
                <td class="text-center"><small>{region["failed_findings"]}</small></td>
                <td class="text-center"><small><span class="badge bg-danger">{region["critical_failures"]}</span></small></td>
                <td class="text-center"><small><span class="badge bg-warning">{region["high_failures"]}</span></small></td>
                <td class="text-center"><small><span class="risk-score risk-{risk_class}">{region["risk_score"]}</span></small></td>
            </tr>
            """

        return f"""
        <table class="table table-sm">
            <thead>
                <tr>
                    <th><small>Region</small></th>
                    <th class="text-center"><small>Total</small></th>
                    <th class="text-center"><small>Failed</small></th>
                    <th class="text-center"><small>Critical</small></th>
                    <th class="text-center"><small>High</small></th>
                    <th class="text-center"><small>Risk</small></th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

    # DISABLED: Heat map functionality temporarily disabled
    # def _build_heat_map_widget(self, heat_map_data: Dict[str, Any], chart_configs: Dict[str, str]) -> str:
    #     """Build risk heat map widget."""
    #     if not heat_map_data or not heat_map_data.get('risk_matrix'):
    #         return ""
    #
    #     return f"""
    #     <div class="row mb-4">
    #         <div class="col-12">
    #             <div class="card">
    #                 <div class="card-header">
    #                     <h5>🔥 Risk Heat Map by Service & Account</h5>
    #                 </div>
    #                 <div class="card-body">
    #                     <div class="row">
    #                         <div class="col-md-9">
    #                             <canvas id="heatMapChart" height="400"></canvas>
    #                         </div>
    #                         <div class="col-md-3">
    #                             <h6>Risk Level Legend</h6>
    #                             <div class="mb-3">
    #                                 <div class="d-flex align-items-center mb-2">
    #                                     <div class="risk-legend-color" style="background-color: #dc3545; width: 20px; height: 20px; border-radius: 50%; margin-right: 8px;"></div>
    #                                     <small>Critical (70-100)</small>
    #                                 </div>
    #                                 <div class="d-flex align-items-center mb-2">
    #                                     <div class="risk-legend-color" style="background-color: #fd7e14; width: 20px; height: 20px; border-radius: 50%; margin-right: 8px;"></div>
    #                                     <small>High (40-69)</small>
    #                                 </div>
    #                                 <div class="d-flex align-items-center mb-2">
    #                                     <div class="risk-legend-color" style="background-color: #ffc107; width: 20px; height: 20px; border-radius: 50%; margin-right: 8px;"></div>
    #                                     <small>Medium (20-39)</small>
    #                                 </div>
    #                                 <div class="d-flex align-items-center mb-2">
    #                                     <div class="risk-legend-color" style="background-color: #28a745; width: 20px; height: 20px; border-radius: 50%; margin-right: 8px;"></div>
    #                                     <small>Low (1-19)</small>
    #                                 </div>
    #                                 <div class="d-flex align-items-center mb-2">
    #                                     <div class="risk-legend-color" style="background-color: #f8f9fa; width: 20px; height: 20px; border-radius: 50%; margin-right: 8px; border: 1px solid #dee2e6;"></div>
    #                                     <small>No Risk (0)</small>
    #                                 </div>
    #                             </div>
    #                             <div class="alert alert-info">
    #                                 <small>
    #                                     <strong>How to read:</strong><br>
    #                                     • Larger circles = more findings<br>
    #                                     • Color intensity = risk level<br>
    #                                     • Hover for details
    #                                 </small>
    #                             </div>
    #                             {self._build_heat_map_summary(heat_map_data)}
    #                         </div>
    #                     </div>
    #                 </div>
    #             </div>
    #         </div>
    #     </div>
    #     """
    #
    # def _build_heat_map_summary(self, heat_map_data: Dict[str, Any]) -> str:
    #     """Build heat map summary statistics."""
    #     if not heat_map_data or not heat_map_data.get('risk_matrix'):
    #         return ""
    #
    #     # Find top risk combinations
    #     top_risks = []
    #     for service_row in heat_map_data['risk_matrix']:
    #         for cell in service_row:
    #             if cell['risk_score'] > 0:
    #                 top_risks.append(cell)
    #
    #     # Sort by risk score and take top 3
    #     top_risks.sort(key=lambda x: x['risk_score'], reverse=True)
    #     top_risks = top_risks[:3]
    #
    #     if not top_risks:
    #         return "<p><small>No high-risk combinations found.</small></p>"
    #
    #     rows = ""
    #     for risk in top_risks:
    #         # Get account name
    #         account_name = next((acc['name'] for acc in heat_map_data['accounts'] if acc['id'] == risk['account']), risk['account'])
    #         risk_class = self._get_risk_class(risk['risk_score'])
    #
    #         rows += f"""
    #         <tr>
    #             <td><small>{risk['service']}</small></td>
    #             <td><small>{account_name}</small></td>
    #             <td><small><span class="risk-score risk-{risk_class}">{risk['risk_score']}</span></small></td>
    #         </tr>
    #         """
    #
    #     return f"""
    #     <div class="mt-3">
    #         <h6>Top Risk Combinations</h6>
    #         <table class="table table-sm">
    #             <thead>
    #                 <tr>
    #                     <th><small>Service</small></th>
    #                     <th><small>Account</small></th>
    #                     <th><small>Risk</small></th>
    #                 </tr>
    #             </thead>
    #             <tbody>
    #                 {rows}
    #             </tbody>
    #         </table>
    #     </div>
    #     """

    def _build_roadmap_widget(
        self, roadmap_data: Dict[str, Any], chart_configs: Dict[str, str]
    ) -> str:
        """Build improvement roadmap widget with timeline and priorities."""
        if not roadmap_data or not roadmap_data.get("summary", {}).get("total_issues"):
            return ""

        summary = roadmap_data["summary"]
        immediate = roadmap_data["immediate"]
        short_term = roadmap_data["short_term"]
        long_term = roadmap_data["long_term"]

        return f"""
        <div class="row mb-4" id="roadmap">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>🛣️ Security Improvement Roadmap</h5>
                        <p class="mb-0 text-muted">Strategic plan to address {summary["total_issues"]} security findings</p>
                    </div>
                    <div class="card-body">
                        <div class="row mb-4">
                            <div class="col-md-8">
                                <canvas id="roadmapChart" height="300"></canvas>
                            </div>
                            <div class="col-md-4">
                                <div class="roadmap-summary">
                                    <h6>📊 Roadmap Summary</h6>
                                    <div class="mb-3">
                                        <div class="d-flex justify-content-between">
                                            <span>Total Issues:</span>
                                            <strong>{summary["total_issues"]}</strong>
                                        </div>
                                        <div class="d-flex justify-content-between">
                                            <span>Critical Issues:</span>
                                            <strong class="text-danger">{summary["critical_count"]}</strong>
                                        </div>
                                        <div class="d-flex justify-content-between">
                                            <span>High Priority:</span>
                                            <strong class="text-warning">{summary["high_count"]}</strong>
                                        </div>
                                    </div>

                                    <div class="alert alert-info">
                                        <small>
                                            <strong>💡 Recommendation:</strong><br>
                                            Focus on immediate fixes first to reduce critical risk exposure quickly.
                                        </small>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-4">
                                <div class="card border-danger">
                                    <div class="card-header bg-danger text-white">
                                        <h6 class="mb-0">🚨 Immediate (1-2 weeks)</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="mb-2">
                                            <strong>{immediate["count"]} issues</strong>
                                        </div>
                                        <p class="small text-muted mb-3">{immediate["description"]}</p>
                                        {self._build_roadmap_items_list(immediate["items"][:5], "immediate")}
                                    </div>
                                </div>
                            </div>

                            <div class="col-md-4">
                                <div class="card border-warning">
                                    <div class="card-header bg-warning text-dark">
                                        <h6 class="mb-0">⚠️ Short Term (1-2 months)</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="mb-2">
                                            <strong>{short_term["count"]} issues</strong>
                                        </div>
                                        <p class="small text-muted mb-3">{short_term["description"]}</p>
                                        {self._build_roadmap_items_list(short_term["items"][:5], "short_term")}
                                    </div>
                                </div>
                            </div>

                            <div class="col-md-4">
                                <div class="card border-success">
                                    <div class="card-header bg-success text-white">
                                        <h6 class="mb-0">📈 Long Term (3-6 months)</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="mb-2">
                                            <strong>{long_term["count"]} issues</strong>
                                        </div>
                                        <p class="small text-muted mb-3">{long_term["description"]}</p>
                                        {self._build_roadmap_items_list(long_term["items"][:5], "long_term")}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_roadmap_items_list(
        self, items: List[Dict[str, Any]], category: str
    ) -> str:
        """Build roadmap items list for a specific category."""
        if not items:
            return "<p class='text-muted small'>No items in this category</p>"

        items_html = ""
        for i, item in enumerate(items):
            severity_class = {
                "Critical": "danger",
                "High": "warning",
                "Medium": "info",
                "Low": "secondary",
            }.get(item["severity"], "secondary")

            # Use full title without truncation
            title = self._esc(item["title"])
            service = self._esc(item["service"])
            description = self._esc(item["description"])
            severity = self._esc(item["severity"])

            items_html += f"""
            <div class="roadmap-item mb-2 p-2 border-start border-3 border-{severity_class}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1 roadmap-item-content">
                        <small class="fw-bold roadmap-item-title" title="{title}">{title}</small>
                        <div class="text-muted" style="font-size: 0.75rem;">
                            {service} • {item["affected_resources"]} resource(s)
                        </div>
                        <div class="text-muted" style="font-size: 0.75rem;">
                            {description}
                        </div>
                    </div>
                    <div class="text-end flex-shrink-0">
                        <span class="badge bg-{severity_class}">{severity}</span>
                    </div>
                </div>
            </div>
            """

            if i >= 4:  # Limit to 5 items
                break

        return items_html

    def _build_detailed_tables(
        self,
        account_analysis: List[Dict[str, Any]],
        service_analysis: List[Dict[str, Any]],
        top_checks: List[Dict[str, Any]],
    ) -> str:
        """Build detailed analysis tables."""
        return f"""
        <div class="row mb-4" id="details">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Account Security Details</h5>
                    </div>
                    <div class="card-body">
                        {self._build_account_filters()}
                        <div class="table-responsive">
                            {self._build_account_table(account_analysis)}
                        </div>
                        {self._build_account_pagination()}
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Service Vulnerability Analysis</h5>
                    </div>
                    <div class="card-body">
                        {self._build_service_filters()}
                        <div class="table-responsive">
                            {self._build_service_table(service_analysis)}
                        </div>
                        {self._build_service_pagination()}
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_compliance_section(self, compliance_analysis: Dict[str, Any]) -> str:
        """Build compliance analysis section with severity breakdown."""
        # Temporarily disabled - will be re-enabled later
        return '<div id="compliance"></div>'

    def _build_compliance_table(self, frameworks: List[Dict[str, Any]]) -> str:
        """Build compliance framework summary table.

        Args:
            frameworks: List of compliance framework data

        Returns:
            HTML table string
        """
        if not frameworks:
            return "<p>No compliance data available.</p>"

        rows = ""
        for fw in frameworks[:10]:  # Limit to top 10
            risk_class = self._get_risk_class(fw.get("risk_score", 0))
            critical = fw.get("critical_violations", 0)
            high = fw.get("high_violations", 0)
            total = fw.get("violations", 0)

            # Add warning indicators for high-risk frameworks
            warning_icon = ""
            if critical > 0:
                warning_icon = "🚨"
            elif high > 0:
                warning_icon = "⚠️"

            fw_name = self._esc(fw["framework"])
            rows += f"""
            <tr>
                <td>
                    <small><strong>{fw_name}</strong> {warning_icon}</small>
                </td>
                <td class="text-center">
                    <small>{total}</small>
                </td>
                <td class="text-center">
                    <small><span class="risk-score risk-{risk_class}">{fw.get("risk_score", 0)}</span></small>
                </td>
            </tr>
            """

        return f"""
        <table class="table table-sm">
            <thead>
                <tr>
                    <th><small>Framework</small></th>
                    <th class="text-center"><small>Total</small></th>
                    <th class="text-center"><small>Risk</small></th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

    def _build_account_table(self, account_analysis: List[Dict[str, Any]]) -> str:
        """Build account analysis table with filtering and pagination support."""
        if not account_analysis:
            return "<p>No account data available.</p>"

        rows = ""
        for (
            account
        ) in account_analysis:  # Include all accounts for JavaScript filtering
            risk_class = self._get_risk_class(account["risk_score"])
            acct_name = self._esc(account["account_name"])
            acct_id = self._esc(account["account_id"])
            rows += f"""
            <tr class="account-row"
                data-account-name="{acct_name.lower()}"
                data-account-id="{acct_id}"
                data-risk-score="{account["risk_score"]}"
                data-pass-rate="{account["pass_rate"]}">
                <td>{acct_name}</td>
                <td><code>{acct_id}</code></td>
                <td>{account["total_findings"]}</td>
                <td>{account["failed_findings"]}</td>
                <td>{account["pass_rate"]}%</td>
                <td><span class="badge bg-danger">{account["critical_failures"]}</span></td>
                <td><span class="badge bg-warning">{account["high_failures"]}</span></td>
                <td><span class="risk-score risk-{risk_class}">{account["risk_score"]}</span></td>
            </tr>
            """

        return f"""
        <table class="table table-striped" id="accountTable">
            <thead>
                <tr>
                    <th>Account</th>
                    <th>Account Number</th>
                    <th>Total Findings</th>
                    <th>Failed</th>
                    <th>Pass Rate</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody id="accountTableBody">
                {rows}
            </tbody>
        </table>
        """

    def _build_account_filters(self) -> str:
        """Build account filtering controls."""
        return f"""
        <div class="row mb-3">
            <div class="col-md-4">
                <label for="accountNameFilter" class="form-label">Filter by Account Name:</label>
                <input type="text" id="accountNameFilter" class="form-control" placeholder="Enter account name..." onkeyup="filterAccountTable()">
            </div>
            <div class="col-md-4">
                <label for="accountNumberFilter" class="form-label">Filter by Account Number:</label>
                <input type="text" id="accountNumberFilter" class="form-control" placeholder="Enter account number..." onkeyup="filterAccountTable()">
            </div>
            <div class="col-md-4 d-flex align-items-end">
                <button type="button" class="btn btn-outline-secondary" onclick="clearAccountFilters()">
                    🗑️ Clear Filters
                </button>
            </div>
        </div>
        """

    def _build_account_pagination(self) -> str:
        """Build account table pagination controls."""
        return f"""
        <div class="row mt-3">
            <div class="col-md-6">
                <div id="accountTableInfo" class="text-muted">
                    <!-- Table info will be populated by JavaScript -->
                </div>
            </div>
            <div class="col-md-6">
                <nav aria-label="Account table pagination">
                    <ul class="pagination pagination-sm justify-content-end" id="accountPagination">
                        <!-- Pagination will be populated by JavaScript -->
                    </ul>
                </nav>
            </div>
        </div>
        """

    def _build_service_table(self, service_analysis: List[Dict[str, Any]]) -> str:
        """Build service analysis table with filtering and pagination support."""
        if not service_analysis:
            return "<p>No service data available.</p>"

        # Sort by critical failures (highest first), then by high failures, then by risk score
        sorted_services = sorted(
            service_analysis,
            key=lambda x: (x["critical_failures"], x["high_failures"], x["risk_score"]),
            reverse=True,
        )

        rows = ""
        for service in sorted_services:  # Include all services for JavaScript filtering
            risk_class = self._get_risk_class(service["risk_score"])
            svc_name = self._esc(service["service_name"])
            rows += f"""
            <tr class="service-row"
                data-service-name="{svc_name.lower()}"
                data-critical-failures="{service["critical_failures"]}"
                data-high-failures="{service["high_failures"]}"
                data-risk-score="{service["risk_score"]}"
                data-failure-rate="{service["failure_rate"]}">
                <td>{svc_name}</td>
                <td>{service["total_findings"]}</td>
                <td>{service["failed_findings"]}</td>
                <td>{service["failure_rate"]}%</td>
                <td><span class="badge bg-danger">{service["critical_failures"]}</span></td>
                <td><span class="badge bg-warning">{service["high_failures"]}</span></td>
                <td><span class="risk-score risk-{risk_class}">{service["risk_score"]}</span></td>
            </tr>
            """

        return f"""
        <table class="table table-striped" id="serviceTable">
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Total Findings</th>
                    <th>Failed</th>
                    <th>Failure Rate</th>
                    <th>Critical ↓</th>
                    <th>High</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody id="serviceTableBody">
                {rows}
            </tbody>
        </table>
        """

    def _build_service_filters(self) -> str:
        """Build service filtering controls."""
        return f"""
        <div class="row mb-3">
            <div class="col-md-6">
                <label for="serviceNameFilter" class="form-label">Filter by Service Name:</label>
                <input type="text" id="serviceNameFilter" class="form-control" placeholder="Enter service name..." onkeyup="filterServiceTable()">
            </div>
            <div class="col-md-6 d-flex align-items-end">
                <button type="button" class="btn btn-outline-secondary me-2" onclick="clearServiceFilters()">
                    🗑️ Clear Filters
                </button>
                <div class="text-muted small">
                    <i>Sorted by Critical Failures (highest first)</i>
                </div>
            </div>
        </div>
        """

    def _build_service_pagination(self) -> str:
        """Build service table pagination controls."""
        return f"""
        <div class="row mt-3">
            <div class="col-md-6">
                <div id="serviceTableInfo" class="text-muted">
                    <!-- Table info will be populated by JavaScript -->
                </div>
            </div>
            <div class="col-md-6">
                <nav aria-label="Service table pagination">
                    <ul class="pagination pagination-sm justify-content-end" id="servicePagination">
                        <!-- Pagination will be populated by JavaScript -->
                    </ul>
                </nav>
            </div>
        </div>
        """

    def _build_chart_initialization(self, chart_configs: Dict[str, str]) -> str:
        """Build chart initialization JavaScript."""
        js_code = """
        // Global chart instances for filtering
        let chartInstances = {};
        let originalChartData = {};
        """

        chart_mappings = {
            "severity_chart": "severityChart",
            "account_chart": "accountChart",
            "service_chart": "serviceChart",
            "checks_chart": "checksChart",
            "regions_chart": "regionsChart",
            "roadmap_chart": "roadmapChart",
            # 'heat_map_chart': 'heatMapChart'  # Temporarily disabled
            # 'compliance_chart': 'complianceChart'  # Temporarily disabled
        }

        for config_key, canvas_id in chart_mappings.items():
            if config_key in chart_configs:
                # DISABLED: Special handling for heat map chart
                # if config_key == 'heat_map_chart':
                #     js_code += f"""
                #     try {{
                #         const {canvas_id}Ctx = document.getElementById('{canvas_id}');
                #         if ({canvas_id}Ctx) {{
                #             const chartConfig = {chart_configs[config_key]};
                #             const metadata = chartConfig.metadata;
                #
                #             // Add custom axis label callbacks
                #             chartConfig.options.scales.x.ticks.callback = function(value) {{
                #                 return metadata.accounts[value] || '';
                #             }};
                #
                #             chartConfig.options.scales.y.ticks.callback = function(value) {{
                #                 return metadata.services[value] || '';
                #             }};
                #
                #             // Add custom tooltip callbacks
                #             chartConfig.options.plugins.tooltip.callbacks = {{
                #                 title: function(context) {{
                #                     const dataIndex = context[0].dataIndex;
                #                     const point = metadata.dataPoints[dataIndex];
                #                     return point.service + ' × ' + point.account;
                #                 }},
                #                 label: function(context) {{
                #                     const dataIndex = context.dataIndex;
                #                     const point = metadata.dataPoints[dataIndex];
                #                     return [
                #                         'Risk Score: ' + point.risk_score,
                #                         'Failed Findings: ' + point.finding_count,
                #                         'Total Findings: ' + point.total_findings
                #                     ];
                #                 }}
                #             }};
                #
                #             // Remove metadata before creating chart
                #             delete chartConfig.metadata;
                #
                #             chartInstances['{canvas_id}'] = new Chart({canvas_id}Ctx, chartConfig);
                #
                #             // Store original data for filtering
                #             originalChartData['{canvas_id}'] = {{
                #                 labels: [...(chartConfig.data.labels || [])],
                #                 datasets: chartConfig.data.datasets.map(dataset => ({{
                #                     ...dataset,
                #                     data: [...dataset.data]
                #                 }}))
                #             }};
                #         }}
                #     }} catch (error) {{
                #         console.error('Error initializing {canvas_id}:', error);
                #     }}
                #     """
                # Special handling for checks chart to add custom tooltips
                if config_key == "checks_chart":
                    js_code += f"""
                    try {{
                        const {canvas_id}Ctx = document.getElementById('{canvas_id}');
                        if ({canvas_id}Ctx) {{
                            const chartConfig = {chart_configs[config_key]};

                            // Add custom tooltip callbacks for checks chart
                            if (chartConfig.options && chartConfig.options.plugins && chartConfig.options.plugins.tooltip) {{
                                chartConfig.options.plugins.tooltip.callbacks = {{
                                    title: function(context) {{
                                        const dataset = context[0].dataset;
                                        const index = context[0].dataIndex;
                                        return dataset.fullTitles ? dataset.fullTitles[index] : context[0].label;
                                    }},
                                    label: function(context) {{
                                        const dataset = context.dataset;
                                        const index = context.dataIndex;
                                        const labels = [];
                                        labels.push('Failures: ' + context.parsed.x);
                                        if (dataset.severities && dataset.severities[index]) {{
                                            labels.push('Severity: ' + dataset.severities[index]);
                                        }}
                                        if (dataset.checkIds && dataset.checkIds[index]) {{
                                            labels.push('Check ID: ' + dataset.checkIds[index]);
                                        }}
                                        if (dataset.services && dataset.services[index]) {{
                                            labels.push('Service: ' + dataset.services[index]);
                                        }}
                                        return labels;
                                    }},
                                    labelColor: function(context) {{
                                        return {{
                                            borderColor: context.dataset.backgroundColor[context.dataIndex],
                                            backgroundColor: context.dataset.backgroundColor[context.dataIndex]
                                        }};
                                    }}
                                }};
                            }}

                            chartInstances['{canvas_id}'] = new Chart({canvas_id}Ctx, chartConfig);

                            // Store original data for filtering
                            originalChartData['{canvas_id}'] = {{
                                labels: [...chartConfig.data.labels],
                                datasets: chartConfig.data.datasets.map(dataset => ({{
                                    ...dataset,
                                    data: [...dataset.data]
                                }}))
                            }};
                        }}
                    }} catch (error) {{
                        console.error('Error initializing {canvas_id}:', error);
                    }}
                    """
                else:
                    # Special handling for checks chart to add custom tooltips
                    if canvas_id == "checksChart":
                        js_code += f"""
                        try {{
                            const {canvas_id}Ctx = document.getElementById('{canvas_id}');
                            if ({canvas_id}Ctx) {{
                                const chartConfig = {chart_configs[config_key]};

                                // Add custom tooltip callbacks for checks chart
                                if (chartConfig.options && chartConfig.options.plugins && chartConfig.options.plugins.tooltip) {{
                                    chartConfig.options.plugins.tooltip.callbacks = {{
                                        title: function(context) {{
                                            return context[0].dataset.fullTitles[context[0].dataIndex];
                                        }},
                                        label: function(context) {{
                                            const dataset = context.dataset;
                                            const index = context.dataIndex;
                                            return [
                                                `Failures: ${{context.parsed.x}}`,
                                                `Service: ${{dataset.services[index]}}`,
                                                `Severity: ${{dataset.severities[index]}}`,
                                                `Check ID: ${{dataset.checkIds[index]}}`
                                            ];
                                        }}
                                    }};
                                }}

                                chartInstances['{canvas_id}'] = new Chart({canvas_id}Ctx, chartConfig);

                                // Store original data for filtering
                                originalChartData['{canvas_id}'] = {{
                                    labels: [...chartConfig.data.labels],
                                    datasets: chartConfig.data.datasets.map(dataset => ({{
                                        ...dataset,
                                        data: [...dataset.data]
                                    }}))
                                }};
                            }}
                        }} catch (error) {{
                            console.error('Error initializing {canvas_id}:', error);
                        }}
                        """
                    else:
                        js_code += f"""
                        try {{
                            const {canvas_id}Ctx = document.getElementById('{canvas_id}');
                            if ({canvas_id}Ctx) {{
                                const chartConfig = {chart_configs[config_key]};
                                chartInstances['{canvas_id}'] = new Chart({canvas_id}Ctx, chartConfig);

                                // Store original data for filtering
                                originalChartData['{canvas_id}'] = {{
                                    labels: [...chartConfig.data.labels],
                                    datasets: chartConfig.data.datasets.map(dataset => ({{
                                        ...dataset,
                                        data: [...dataset.data]
                                    }}))
                                }};
                            }}
                        }} catch (error) {{
                            console.error('Error initializing {canvas_id}:', error);
                        }}
                        """

        # Add chart update functions
        js_code += self._build_chart_filter_functions()

        return js_code

    def _build_chart_filter_functions(self) -> str:
        """Build JavaScript functions for filtering charts."""
        return ""

    def _build_insights_section(
        self,
        summary_stats: Dict[str, Any],
        account_analysis: List[Dict[str, Any]],
        service_analysis: List[Dict[str, Any]],
    ) -> str:
        """Build security insights and recommendations section."""

        # Generate key insights
        insights = []

        # Critical findings insight
        critical_count = summary_stats.get("critical_findings", 0)
        if critical_count > 0:
            insights.append(
                {
                    "type": "critical",
                    "title": "Critical Security Issues Detected",
                    "description": f"{critical_count} critical security findings require immediate attention.",
                    "recommendation": "Prioritize remediation of critical findings to reduce security risk.",
                }
            )

        # Account security insight
        if account_analysis:
            worst_account = min(account_analysis, key=lambda x: x.get("pass_rate", 100))
            if worst_account.get("pass_rate", 100) < 70:
                insights.append(
                    {
                        "type": "warning",
                        "title": "Account Security Concerns",
                        "description": f"Account '{worst_account.get('account_name', 'Unknown')}' has a {worst_account.get('pass_rate', 0)}% pass rate.",
                        "recommendation": "Review and strengthen security controls for underperforming accounts.",
                    }
                )

        # Service vulnerability insight
        if service_analysis:
            high_risk_services = [
                s for s in service_analysis if s.get("risk_score", 0) > 70
            ]
            if high_risk_services:
                service_names = ", ".join(
                    [s.get("service_name", "Unknown") for s in high_risk_services[:3]]
                )
                insights.append(
                    {
                        "type": "info",
                        "title": "High-Risk Services Identified",
                        "description": f"{len(high_risk_services)} services show elevated risk levels: {service_names}",
                        "recommendation": "Implement additional security controls for high-risk services.",
                    }
                )

        # Overall security posture
        overall_score = summary_stats.get("overall_score", 0)
        if overall_score < 60:
            insights.append(
                {
                    "type": "critical",
                    "title": "Security Posture Needs Improvement",
                    "description": f"Overall security score of {overall_score}% indicates significant security gaps.",
                    "recommendation": "Develop a comprehensive security improvement plan focusing on critical and high-severity findings.",
                }
            )
        elif overall_score < 80:
            insights.append(
                {
                    "type": "warning",
                    "title": "Security Posture is Moderate",
                    "description": f"Overall security score of {overall_score}% shows room for improvement.",
                    "recommendation": "Continue strengthening security controls and monitoring capabilities.",
                }
            )
        else:
            insights.append(
                {
                    "type": "success",
                    "title": "Strong Security Posture",
                    "description": f"Overall security score of {overall_score}% indicates good security practices.",
                    "recommendation": "Maintain current security standards and monitor for new threats.",
                }
            )

        # Build HTML
        insights_html = ""
        for insight in insights:
            icon = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️", "success": "✅"}.get(
                insight["type"], "ℹ️"
            )

            alert_class = {
                "critical": "alert-danger",
                "warning": "alert-warning",
                "info": "alert-info",
                "success": "alert-success",
            }.get(insight["type"], "alert-info")

            insights_html += f"""
            <div class="alert {alert_class}" role="alert">
                <h6 class="alert-heading">{icon} {self._esc(insight["title"])}</h6>
                <p class="mb-2">{self._esc(insight["description"])}</p>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> {self._esc(insight["recommendation"])}</p>
            </div>
            """

        return f"""
        <div class="row mb-4" id="insights">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>🔍 Security Insights & Recommendations</h5>
                    </div>
                    <div class="card-body">
                        {insights_html}

                    </div>
                </div>
            </div>
        </div>
        """

    def _build_score_calculation_section(self) -> str:
        """Build score calculation methodology section."""
        return f"""
        <div class="row mb-4" id="methodology">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>📊 Score Calculation Methodology</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6 class="text-primary">🛡️ Overall Security Score</h6>
                                <p class="text-muted">The Overall Security Score represents the percentage of security controls that are properly configured across all accounts.</p>

                                <div class="bg-light p-3 rounded mb-3">
                                    <h6 class="mb-2">Calculation Formula:</h6>
                                    <code class="d-block mb-2">Security Score = 100 - (Weighted Penalty / Max Possible Penalty × 100)</code>

                                    <h6 class="mb-2 mt-3">Severity Weights:</h6>
                                    <ul class="list-unstyled">
                                        <li><span class="badge bg-danger me-2">Critical</span> Weight: 10</li>
                                        <li><span class="badge bg-warning me-2">High</span> Weight: 7</li>
                                        <li><span class="badge bg-info me-2">Medium</span> Weight: 4</li>
                                        <li><span class="badge bg-success me-2">Low</span> Weight: 2</li>
                                        <li><span class="badge bg-secondary me-2">Info</span> Weight: 1</li>
                                    </ul>
                                </div>

                                <div class="alert alert-info">
                                    <small>
                                        <strong>Example:</strong> If you have 1 Critical failure (10 points) out of 100 total findings,
                                        the penalty would be 10/1000 = 1%, resulting in a 99% security score.
                                    </small>
                                </div>
                            </div>

                            <div class="col-md-6">
                                <h6 class="text-primary">⚠️ Risk Score (Per Account/Service)</h6>
                                <p class="text-muted">Risk Scores are calculated for individual accounts and services based on their failed security findings.</p>

                                <div class="bg-light p-3 rounded mb-3">
                                    <h6 class="mb-2">Calculation Formula:</h6>
                                    <code class="d-block mb-2">Risk Score = (Weighted Failed Findings / Max Possible × 100)</code>

                                    <h6 class="mb-2 mt-3">Risk Score Interpretation:</h6>
                                    <ul class="list-unstyled">
                                        <li><span class="risk-score risk-high me-2">70-100</span> High Risk</li>
                                        <li><span class="risk-score risk-medium me-2">40-69</span> Medium Risk</li>
                                        <li><span class="risk-score risk-low me-2">0-39</span> Low Risk</li>
                                    </ul>
                                </div>

                                <div class="alert alert-warning">
                                    <small>
                                        <strong>Note:</strong> Risk Scores focus only on failed findings, while the Overall Security Score
                                        considers all findings (passed and failed) to provide a comprehensive security posture view.
                                    </small>
                                </div>
                            </div>
                        </div>

                        <hr class="my-4">

                        <div class="row">
                            <div class="col-12">
                                <h6 class="text-primary">🎯 Key Differences</h6>
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>Metric</th>
                                                <th>Scope</th>
                                                <th>Purpose</th>
                                                <th>Range</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td><strong>Overall Security Score</strong></td>
                                                <td>All findings (passed + failed)</td>
                                                <td>Comprehensive security posture</td>
                                                <td>0-100% (higher is better)</td>
                                            </tr>
                                            <tr>
                                                <td><strong>Risk Score</strong></td>
                                                <td>Failed findings only</td>
                                                <td>Risk level assessment</td>
                                                <td>0-100 (higher is worse)</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="mt-3">
                            <div class="alert alert-light border">
                                <h6 class="mb-2">💡 Understanding Your Scores</h6>
                                <ul class="mb-0">
                                    <li><strong>High Security Score (80%+):</strong> Good security posture with most controls properly configured</li>
                                    <li><strong>Medium Security Score (60-79%):</strong> Moderate security posture with room for improvement</li>
                                    <li><strong>Low Security Score (<60%):</strong> Significant security gaps requiring immediate attention</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _get_css_styles(self) -> str:
        """Get CSS styles for the dashboard."""
        return """
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .dashboard-header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        .dashboard-header h1 {
            color: white !important;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
            margin-bottom: 0.5rem;
        }
        .dashboard-header .lead {
            color: rgba(255, 255, 255, 0.9) !important;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
            margin-bottom: 1rem;
        }
        .dashboard-header .generation-time {
            color: rgba(255, 255, 255, 0.8) !important;
            font-size: 0.9rem;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
        }
        .summary-card {
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-2px);
        }
        .security-score {
            font-size: 1.2rem;
        }
        .score-label {
            color: white !important;
            font-weight: 500;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
            margin-right: 0.5rem;
        }
        .score-value {
            font-weight: bold;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .score-high {
            background-color: #d4edda;
            color: #155724;
            border: 2px solid #c3e6cb;
        }
        .score-medium {
            background-color: #fff3cd;
            color: #856404;
            border: 2px solid #ffeaa7;
        }
        .score-low {
            background-color: #f8d7da;
            color: #721c24;
            border: 2px solid #f5c6cb;
        }
        .risk-score {
            font-weight: bold;
            padding: 0.25rem 0.5rem;
            border-radius: 15px;
        }
        .risk-high { background-color: #f8d7da; color: #721c24; }
        .risk-medium { background-color: #fff3cd; color: #856404; }
        .risk-low { background-color: #d4edda; color: #155724; }
        .card {
            border: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 1rem;
        }
        .card-header {
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
        }
        .table th {
            border-top: none;
            font-weight: 600;
            background-color: #f8f9fa;
        }

        /* Navigation Styles */
        .main-content {
            margin-top: 70px; /* Account for fixed navbar */
            transition: margin-left 0.3s ease;
        }

        .sidebar {
            position: fixed;
            top: 56px; /* Below navbar */
            left: -300px;
            width: 300px;
            height: calc(100vh - 56px);
            background: #fff;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
            transition: left 0.3s ease;
            z-index: 1040;
            overflow-y: auto;
        }

        .sidebar.show {
            left: 0;
        }

        .sidebar-header {
            padding: 1rem;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: between;
            align-items: center;
        }

        .sidebar-content {
            padding: 1rem;
        }

        .nav-section {
            margin-bottom: 2rem;
        }

        .nav-section h6 {
            color: #6c757d;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.75rem;
        }

        .sidebar .nav-link {
            color: #495057;
            padding: 0.5rem 0.75rem;
            border-radius: 0.375rem;
            transition: all 0.2s ease;
            font-size: 0.875rem;
        }

        .sidebar .nav-link:hover {
            background-color: #f8f9fa;
            color: #007bff;
            text-decoration: none;
        }

        .sidebar .nav-link i {
            width: 20px;
            margin-right: 0.5rem;
        }

        .sidebar-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1030;
            display: none;
        }

        .sidebar-overlay.show {
            display: block;
        }

        /* Smooth scrolling */
        html {
            scroll-behavior: smooth;
        }

        /* Section spacing for navigation */
        .row[id] {
            scroll-margin-top: 80px;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .main-content {
                margin-top: 60px;
            }

            .sidebar {
                top: 60px;
                height: calc(100vh - 60px);
            }
        }

        /* Print Styles */
        @media print {
            /* Hide navigation elements */
            .navbar,
            .sidebar,
            .sidebar-overlay,
            .btn {
                display: none !important;
            }

            /* Reset main content margins */
            .main-content {
                margin-top: 0 !important;
                margin-left: 0 !important;
            }

            /* Optimize layout for print */
            body {
                background: white !important;
                color: black !important;
                font-size: 12pt;
                line-height: 1.4;
            }

            /* Ensure dashboard header prints nicely */
            .dashboard-header {
                background: #2c3e50 !important;
                color: white !important;
                padding: 1rem !important;
                margin-bottom: 1rem !important;
                page-break-inside: avoid;
            }

            /* Optimize cards for print */
            .card {
                border: 1px solid #ddd !important;
                box-shadow: none !important;
                margin-bottom: 1rem !important;
                page-break-inside: avoid;
            }

            .card-header {
                background: #f8f9fa !important;
                border-bottom: 1px solid #ddd !important;
                font-weight: bold;
            }

            /* Optimize tables for print */
            .table {
                font-size: 10pt;
            }

            .table th,
            .table td {
                padding: 0.25rem !important;
                border: 1px solid #ddd !important;
            }

            /* Hide interactive elements */
            .form-control,
            .form-select,
            .alert {
                display: none !important;
            }

            /* Optimize charts for print */
            canvas {
                max-width: 100% !important;
                height: auto !important;
            }

            /* Page break controls */
            .row[id] {
                page-break-before: auto;
                page-break-after: auto;
                page-break-inside: avoid;
            }

            /* Ensure badges and scores are visible */
            .badge,
            .risk-score,
            .score-value {
                border: 1px solid #333 !important;
                background: white !important;
                color: black !important;
            }

            /* Hide filter sections */
            .card:has(.form-control),
            .card:has(.form-select) {
                display: none !important;
            }

            /* Optimize spacing */
            .container-fluid {
                padding: 0 !important;
            }

            .row {
                margin: 0 !important;
            }

            .col-md-6,
            .col-md-4,
            .col-md-3,
            .col-12 {
                padding: 0.25rem !important;
            }
        }

        /* Roadmap Item Styles */
        .roadmap-item {
            transition: all 0.2s ease;
        }

        .roadmap-item:hover {
            background-color: #f8f9fa;
            border-radius: 0.375rem;
        }

        .roadmap-item-content {
            min-width: 0; /* Allow flex item to shrink */
            margin-right: 0.75rem;
        }

        .roadmap-item-title {
            display: block;
            line-height: 1.3;
            word-wrap: break-word;
            overflow-wrap: break-word;
            hyphens: auto;
        }

        /* Ensure badges don't wrap */
        .flex-shrink-0 {
            flex-shrink: 0;
        }


        """

    def _get_javascript_code(self) -> str:
        """Get JavaScript code for dashboard functionality."""
        return """
        // Global data storage for filtering
        let originalData = {};
        let currentFilter = 'all';



        // Add insights toggle functionality
        function toggleInsights(sectionId) {
            const section = document.getElementById(sectionId);
            const button = event.target;

            if (section.style.display === 'none') {
                section.style.display = 'block';
                button.textContent = button.textContent.replace('Show', 'Hide');
            } else {
                section.style.display = 'none';
                button.textContent = button.textContent.replace('Hide', 'Show');
            }
        }

        // Initialize original data for filtering
        function initializeFilterData() {
            originalData = {
                critical: parseInt(document.getElementById('criticalCount').textContent),
                high: parseInt(document.getElementById('highCount').textContent),
                total: parseInt(document.getElementById('totalCount').textContent),
                accounts: parseInt(document.getElementById('accountCount').textContent)
            };
        }

        // Apply status filter
        function applyStatusFilter() {
            const filter = document.getElementById('statusFilter').value;
            currentFilter = filter;

            const filterInfo = document.getElementById('filterInfo');

            if (filter === 'all') {
                // Show all findings
                document.getElementById('criticalCount').textContent = originalData.critical;
                document.getElementById('highCount').textContent = originalData.high;
                document.getElementById('totalCount').textContent = originalData.total;
                document.getElementById('totalLabel').textContent = 'Total Findings';
                filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing all findings across all statuses</small>';
                filterInfo.className = 'alert alert-info mb-0';
            } else if (filter === 'Failed') {
                // Show only failed findings (this is what critical/high represent)
                document.getElementById('criticalCount').textContent = originalData.critical;
                document.getElementById('highCount').textContent = originalData.high;
                document.getElementById('totalCount').textContent = originalData.critical + originalData.high;
                document.getElementById('totalLabel').textContent = 'Failed Findings';
                filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-danger">FAILED</span> findings</small>';
                filterInfo.className = 'alert alert-danger mb-0';
            } else if (filter === 'Passed') {
                // Show only passed findings
                const passedFindings = originalData.total - (originalData.critical + originalData.high);
                document.getElementById('criticalCount').textContent = '0';
                document.getElementById('highCount').textContent = '0';
                document.getElementById('totalCount').textContent = passedFindings;
                document.getElementById('totalLabel').textContent = 'Passed Findings';
                filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-success">PASSED</span> findings</small>';
                filterInfo.className = 'alert alert-success mb-0';
            } else if (filter === 'Manual') {
                // Show manual findings (estimated)
                document.getElementById('criticalCount').textContent = '0';
                document.getElementById('highCount').textContent = '0';
                document.getElementById('totalCount').textContent = '0';
                document.getElementById('totalLabel').textContent = 'Manual Findings';
                filterInfo.innerHTML = '<small><strong>Current View:</strong> Showing only <span class="badge bg-warning">MANUAL</span> findings</small>';
                filterInfo.className = 'alert alert-warning mb-0';
            }

            // Update charts based on filter
            updateSeverityChart(filter);
            updateAccountChart(filter);
            // updateComplianceChart(filter);  // Temporarily disabled
        }

        // Update severity distribution chart based on filter
        function updateSeverityChart(filter) {
            const chart = chartInstances['severityChart'];
            if (!chart || !originalChartData['severityChart']) return;

            const originalData = originalChartData['severityChart'];
            let newData = [...originalData.datasets[0].data];
            let newLabels = [...originalData.labels];

            if (filter === 'Failed') {
                // Show only Critical and High (failed findings)
                const criticalIndex = newLabels.indexOf('Critical');
                const highIndex = newLabels.indexOf('High');
                const mediumIndex = newLabels.indexOf('Medium');
                const lowIndex = newLabels.indexOf('Low');

                // Zero out Medium and Low for failed filter
                if (mediumIndex !== -1) newData[mediumIndex] = 0;
                if (lowIndex !== -1) newData[lowIndex] = 0;

            } else if (filter === 'Passed') {
                // Show only Medium and Low (passed findings)
                const criticalIndex = newLabels.indexOf('Critical');
                const highIndex = newLabels.indexOf('High');

                // Zero out Critical and High for passed filter
                if (criticalIndex !== -1) newData[criticalIndex] = 0;
                if (highIndex !== -1) newData[highIndex] = 0;

            } else if (filter === 'Manual') {
                // Zero out all data for manual (no manual findings in current data)
                newData = newData.map(() => 0);
            }
            // 'all' filter shows original data (no changes needed)

            chart.data.datasets[0].data = newData;
            chart.update();
        }

        // Update account comparison chart based on filter
        function updateAccountChart(filter) {
            const chart = chartInstances['accountChart'];
            if (!chart || !originalChartData['accountChart']) return;

            const originalData = originalChartData['accountChart'];

            if (filter === 'all') {
                // Restore original data for all datasets
                chart.data.datasets.forEach((dataset, index) => {
                    dataset.data = [...originalData.datasets[index].data];
                });

            } else if (filter === 'Failed') {
                // Show only Critical and High findings (failed)
                chart.data.datasets.forEach((dataset, index) => {
                    if (dataset.label === 'Critical' || dataset.label === 'High') {
                        dataset.data = [...originalData.datasets[index].data];
                    } else {
                        // Zero out Medium and Low
                        dataset.data = originalData.datasets[index].data.map(() => 0);
                    }
                });

            } else if (filter === 'Passed') {
                // Show only Medium and Low findings (passed)
                chart.data.datasets.forEach((dataset, index) => {
                    if (dataset.label === 'Medium' || dataset.label === 'Low') {
                        dataset.data = [...originalData.datasets[index].data];
                    } else {
                        // Zero out Critical and High
                        dataset.data = originalData.datasets[index].data.map(() => 0);
                    }
                });

            } else if (filter === 'Manual') {
                // Zero out all data for manual (no manual findings in current data)
                chart.data.datasets.forEach((dataset, index) => {
                    dataset.data = originalData.datasets[index].data.map(() => 0);
                });
            }

            chart.update();
        }

        // Update compliance chart based on filter - DISABLED
        // function updateComplianceChart(filter) { ... }

        // Account table filtering and pagination
        let currentAccountPage = 1;
        let accountsPerPage = 10;
        let filteredAccountRows = [];

        function filterAccountTable() {
            const nameFilter = document.getElementById('accountNameFilter').value.toLowerCase();
            const numberFilter = document.getElementById('accountNumberFilter').value.toLowerCase();
            const allRows = document.querySelectorAll('.account-row');

            filteredAccountRows = Array.from(allRows).filter(row => {
                const accountName = row.getAttribute('data-account-name');
                const accountId = row.getAttribute('data-account-id').toLowerCase();

                const nameMatch = !nameFilter || accountName.includes(nameFilter);
                const numberMatch = !numberFilter || accountId.includes(numberFilter);

                return nameMatch && numberMatch;
            });

            currentAccountPage = 1;
            displayAccountPage();
            updateAccountPagination();
        }

        function displayAccountPage() {
            const allRows = document.querySelectorAll('.account-row');

            // Hide all rows first
            allRows.forEach(row => row.style.display = 'none');

            // Calculate start and end indices
            const startIndex = (currentAccountPage - 1) * accountsPerPage;
            const endIndex = startIndex + accountsPerPage;

            // Show rows for current page
            filteredAccountRows.slice(startIndex, endIndex).forEach(row => {
                row.style.display = '';
            });

            updateAccountTableInfo();
        }

        function updateAccountPagination() {
            const totalPages = Math.ceil(filteredAccountRows.length / accountsPerPage);
            const pagination = document.getElementById('accountPagination');

            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }

            let paginationHTML = '';

            // Previous button
            if (currentAccountPage > 1) {
                paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${currentAccountPage - 1})">Previous</a></li>`;
            } else {
                paginationHTML += `<li class="page-item disabled"><span class="page-link">Previous</span></li>`;
            }

            // Page numbers
            const maxVisiblePages = 5;
            let startPage = Math.max(1, currentAccountPage - Math.floor(maxVisiblePages / 2));
            let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

            if (endPage - startPage + 1 < maxVisiblePages) {
                startPage = Math.max(1, endPage - maxVisiblePages + 1);
            }

            for (let i = startPage; i <= endPage; i++) {
                if (i === currentAccountPage) {
                    paginationHTML += `<li class="page-item active"><span class="page-link">${i}</span></li>`;
                } else {
                    paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${i})">${i}</a></li>`;
                }
            }

            // Next button
            if (currentAccountPage < totalPages) {
                paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeAccountPage(${currentAccountPage + 1})">Next</a></li>`;
            } else {
                paginationHTML += `<li class="page-item disabled"><span class="page-link">Next</span></li>`;
            }

            pagination.innerHTML = paginationHTML;
        }

        function changeAccountPage(page) {
            currentAccountPage = page;
            displayAccountPage();
            updateAccountPagination();
        }

        function updateAccountTableInfo() {
            const totalAccounts = filteredAccountRows.length;
            const startIndex = (currentAccountPage - 1) * accountsPerPage + 1;
            const endIndex = Math.min(currentAccountPage * accountsPerPage, totalAccounts);

            const info = document.getElementById('accountTableInfo');
            if (totalAccounts === 0) {
                info.textContent = 'No accounts found matching the filter criteria.';
            } else {
                info.textContent = `Showing ${startIndex}-${endIndex} of ${totalAccounts} accounts`;
            }
        }

        function clearAccountFilters() {
            document.getElementById('accountNameFilter').value = '';
            document.getElementById('accountNumberFilter').value = '';
            filterAccountTable();
        }

        function initializeAccountTable() {
            const allRows = document.querySelectorAll('.account-row');
            filteredAccountRows = Array.from(allRows);
            displayAccountPage();
            updateAccountPagination();
        }

        // Service table filtering and pagination
        let currentServicePage = 1;
        let servicesPerPage = 10;
        let filteredServiceRows = [];

        function filterServiceTable() {
            const nameFilter = document.getElementById('serviceNameFilter').value.toLowerCase();
            const allRows = document.querySelectorAll('.service-row');

            filteredServiceRows = Array.from(allRows).filter(row => {
                const serviceName = row.getAttribute('data-service-name');
                return !nameFilter || serviceName.includes(nameFilter);
            });

            currentServicePage = 1;
            displayServicePage();
            updateServicePagination();
        }

        function displayServicePage() {
            const allRows = document.querySelectorAll('.service-row');

            // Hide all rows first
            allRows.forEach(row => row.style.display = 'none');

            // Calculate start and end indices
            const startIndex = (currentServicePage - 1) * servicesPerPage;
            const endIndex = startIndex + servicesPerPage;

            // Show rows for current page
            filteredServiceRows.slice(startIndex, endIndex).forEach(row => {
                row.style.display = '';
            });

            updateServiceTableInfo();
        }

        function updateServicePagination() {
            const totalPages = Math.ceil(filteredServiceRows.length / servicesPerPage);
            const pagination = document.getElementById('servicePagination');

            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }

            let paginationHTML = '';

            // Previous button
            if (currentServicePage > 1) {
                paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${currentServicePage - 1})">Previous</a></li>`;
            } else {
                paginationHTML += `<li class="page-item disabled"><span class="page-link">Previous</span></li>`;
            }

            // Page numbers
            const maxVisiblePages = 5;
            let startPage = Math.max(1, currentServicePage - Math.floor(maxVisiblePages / 2));
            let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

            if (endPage - startPage + 1 < maxVisiblePages) {
                startPage = Math.max(1, endPage - maxVisiblePages + 1);
            }

            for (let i = startPage; i <= endPage; i++) {
                if (i === currentServicePage) {
                    paginationHTML += `<li class="page-item active"><span class="page-link">${i}</span></li>`;
                } else {
                    paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${i})">${i}</a></li>`;
                }
            }

            // Next button
            if (currentServicePage < totalPages) {
                paginationHTML += `<li class="page-item"><a class="page-link" href="#" onclick="changeServicePage(${currentServicePage + 1})">Next</a></li>`;
            } else {
                paginationHTML += `<li class="page-item disabled"><span class="page-link">Next</span></li>`;
            }

            pagination.innerHTML = paginationHTML;
        }

        function changeServicePage(page) {
            currentServicePage = page;
            displayServicePage();
            updateServicePagination();
        }

        function updateServiceTableInfo() {
            const totalServices = filteredServiceRows.length;
            const startIndex = (currentServicePage - 1) * servicesPerPage + 1;
            const endIndex = Math.min(currentServicePage * servicesPerPage, totalServices);

            const info = document.getElementById('serviceTableInfo');
            if (totalServices === 0) {
                info.textContent = 'No services found matching the filter criteria.';
            } else {
                info.textContent = `Showing ${startIndex}-${endIndex} of ${totalServices} services`;
            }
        }

        function clearServiceFilters() {
            document.getElementById('serviceNameFilter').value = '';
            filterServiceTable();
        }

        function initializeServiceTable() {
            const allRows = document.querySelectorAll('.service-row');
            filteredServiceRows = Array.from(allRows);
            displayServicePage();
            updateServicePagination();
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            initializeFilterData();
            initializeAccountTable();
            initializeServiceTable();
        });

        // Navigation functionality
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');

            sidebar.classList.toggle('show');
            overlay.classList.toggle('show');
        }

        function scrollToSection(sectionId) {
            const element = document.getElementById(sectionId);
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'start' });
                // Close sidebar on mobile after navigation
                if (window.innerWidth <= 768) {
                    toggleSidebar();
                }
            }
        }





        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(event) {
            const sidebar = document.getElementById('sidebar');
            const sidebarToggle = event.target.closest('[onclick*="toggleSidebar"]');

            if (!sidebar.contains(event.target) && !sidebarToggle && sidebar.classList.contains('show')) {
                toggleSidebar();
            }
        });

        // Handle window resize
        window.addEventListener('resize', function() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');

            if (window.innerWidth > 768 && sidebar.classList.contains('show')) {
                sidebar.classList.remove('show');
                overlay.classList.remove('show');
            }
        });
        """

    def _get_score_class(self, score: float) -> str:
        """Get CSS class for security score."""
        if score >= 80:
            return "high"
        elif score >= 60:
            return "medium"
        else:
            return "low"

    def _get_risk_class(self, risk_score: float) -> str:
        """Get CSS class for risk score."""
        if risk_score >= 70:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"

    def build_html_structure(self, analytics_data: Dict, charts_data: Dict) -> str:
        """Build HTML structure from analytics and charts data."""
        if not analytics_data:
            analytics_data = {}
        if not charts_data:
            charts_data = {}

        return self.build_dashboard(
            summary_stats=analytics_data.get("summary", {}),
            account_analysis=analytics_data.get("accounts", []),
            service_analysis=analytics_data.get("services", []),
            compliance_analysis=analytics_data.get("compliance", {}),
            top_checks=analytics_data.get("top_checks", []),
            chart_configs=charts_data,
        )

    def generate_dashboard(
        self, analytics_data: Dict, charts_data: Dict, output_path: str = None
    ) -> str:
        """Generate dashboard and save to file."""
        html_content = self.build_html_structure(analytics_data, charts_data)

        if output_path is None:
            output_path = "cspm_scan_insights.html"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
