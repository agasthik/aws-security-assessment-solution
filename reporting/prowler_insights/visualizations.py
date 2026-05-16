#!/usr/bin/env python3
"""
Visualizations Module - Interactive chart generation for security dashboard.
"""

import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class ChartGenerator:
    """Generates interactive charts for the security dashboard."""

    def __init__(self):
        """Initialize the chart generator."""
        self.colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Info": "#17a2b8",
            "Failed": "#dc3545",
            "Passed": "#28a745",
            "Manual": "#6c757d",
            "primary": "#007bff",
            "secondary": "#6c757d",
        }

    def create_severity_distribution_chart(
        self, severity_counts: Dict[str, int]
    ) -> str:
        """Create severity distribution pie chart.

        Args:
            severity_counts: Dictionary of severity counts

        Returns:
            Chart.js configuration as JSON string
        """
        if not severity_counts:
            return self._empty_chart_config()

        labels = list(severity_counts.keys())
        data = list(severity_counts.values())
        colors = [self.colors.get(label, "#6c757d") for label in labels]

        config = {
            "type": "pie",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "data": data,
                        "backgroundColor": colors,
                        "borderWidth": 2,
                        "borderColor": "#fff",
                    }
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {
                    "legend": {"position": "bottom"},
                    "tooltip": {"mode": "nearest", "intersect": True},
                },
            },
        }

        return json.dumps(config)

    def create_account_comparison_chart(
        self, account_data: List[Dict[str, Any]]
    ) -> str:
        """Create account security comparison bar chart.

        Args:
            account_data: List of account analysis data

        Returns:
            Chart.js configuration as JSON string
        """
        if not account_data:
            return self._empty_chart_config()

        # Limit to top 10 accounts for readability
        if isinstance(account_data, list):
            top_accounts = account_data[:10]
        elif isinstance(account_data, dict):
            # Convert dict to list of items and take first 10
            top_accounts = list(account_data.items())[:10]
        else:
            top_accounts = []

        labels = []
        values = []
        colors = []

        for acc in top_accounts:
            if isinstance(acc, dict):
                name = acc.get("account_name", str(acc.get("account_id", "Unknown")))
                value = acc.get("failure_count", acc.get("total_findings", 0))
            elif isinstance(acc, tuple) and len(acc) >= 2:
                name = str(acc[0])
                value = acc[1] if isinstance(acc[1], (int, float)) else 0
            else:
                name = str(acc)
                value = 1

            # Truncate long names
            display_name = name[:20] + "..." if len(name) > 20 else name
            labels.append(display_name)
            values.append(value)
            colors.append(self.colors.get("primary", "#007bff"))

        if not labels:
            labels = ["No Data"]
            values = [
                0 if len(acc["account_name"]) > 20 else acc["account_name"]
                for acc in top_accounts
            ]

        critical_data = [acc["critical_failures"] for acc in top_accounts]
        high_data = [acc["high_failures"] for acc in top_accounts]
        medium_data = [acc["medium_failures"] for acc in top_accounts]
        low_data = [acc["low_failures"] for acc in top_accounts]

        config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Critical",
                        "data": critical_data,
                        "backgroundColor": self.colors["Critical"],
                        "stack": "failures",
                    },
                    {
                        "label": "High",
                        "data": high_data,
                        "backgroundColor": self.colors["High"],
                        "stack": "failures",
                    },
                    {
                        "label": "Medium",
                        "data": medium_data,
                        "backgroundColor": self.colors["Medium"],
                        "stack": "failures",
                    },
                    {
                        "label": "Low",
                        "data": low_data,
                        "backgroundColor": self.colors["Low"],
                        "stack": "failures",
                    },
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "scales": {
                    "x": {"stacked": True, "ticks": {"maxRotation": 45}},
                    "y": {"stacked": True, "beginAtZero": True},
                },
                "plugins": {
                    "legend": {"position": "top"},
                    "tooltip": {"mode": "index", "intersect": False},
                },
            },
        }

        return json.dumps(config)

    def create_service_risk_chart(self, service_data: List[Dict[str, Any]]) -> str:
        """Create service risk analysis chart.

        Args:
            service_data: List of service analysis data

        Returns:
            Chart.js configuration as JSON string
        """
        if not service_data:
            return self._empty_chart_config()

        # Limit to top 10 services for readability
        top_services = service_data[:10]

        labels = [svc["service_name"] for svc in top_services]
        risk_scores = [svc["risk_score"] for svc in top_services]
        failure_counts = [svc["failed_findings"] for svc in top_services]

        # Create color gradient based on risk score
        colors = []
        for score in risk_scores:
            if score >= 70:
                colors.append(self.colors["Critical"])
            elif score >= 40:
                colors.append(self.colors["High"])
            elif score >= 20:
                colors.append(self.colors["Medium"])
            else:
                colors.append(self.colors["Low"])

        config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Risk Score",
                        "data": risk_scores,
                        "backgroundColor": colors,
                        "borderWidth": 1,
                        "yAxisID": "y",
                    },
                    {
                        "label": "Failed Findings",
                        "data": failure_counts,
                        "backgroundColor": "rgba(54, 162, 235, 0.6)",
                        "borderColor": "rgba(54, 162, 235, 1)",
                        "borderWidth": 1,
                        "type": "line",
                        "yAxisID": "y1",
                        "tension": 0.4,
                    },
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "interaction": {"mode": "index", "intersect": False},
                "scales": {
                    "x": {
                        "display": True,
                        "title": {"display": True, "text": "Services"},
                        "ticks": {"maxRotation": 45, "minRotation": 45},
                    },
                    "y": {
                        "type": "linear",
                        "display": True,
                        "position": "left",
                        "title": {"display": True, "text": "Risk Score (0-100)"},
                        "beginAtZero": True,
                        "max": 100,
                    },
                    "y1": {
                        "type": "linear",
                        "display": True,
                        "position": "right",
                        "title": {"display": True, "text": "Failed Findings Count"},
                        "beginAtZero": True,
                        "grid": {"drawOnChartArea": False},
                    },
                },
                "plugins": {
                    "legend": {"position": "top"},
                    "tooltip": {"mode": "index", "intersect": False},
                },
            },
        }

        return json.dumps(config)

    def create_compliance_chart(self, compliance_data: Dict[str, Any]) -> str:
        """Create compliance framework violations chart with severity breakdown.

        Args:
            compliance_data: Compliance analysis data

        Returns:
            Chart.js configuration as JSON string
        """
        frameworks = compliance_data.get("frameworks", [])
        if not frameworks:
            return self._empty_chart_config()

        # Limit to top 10 frameworks for readability
        top_frameworks = frameworks[:10]

        labels = [fw["framework"] for fw in top_frameworks]
        critical_data = [fw.get("critical_violations", 0) for fw in top_frameworks]
        high_data = [fw.get("high_violations", 0) for fw in top_frameworks]
        medium_data = [fw.get("medium_violations", 0) for fw in top_frameworks]
        low_data = [fw.get("low_violations", 0) for fw in top_frameworks]
        info_data = [fw.get("info_violations", 0) for fw in top_frameworks]

        config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Critical",
                        "data": critical_data,
                        "backgroundColor": self.colors["Critical"],
                        "borderColor": self.colors["Critical"],
                        "borderWidth": 1,
                        "stack": "violations",
                    },
                    {
                        "label": "High",
                        "data": high_data,
                        "backgroundColor": self.colors["High"],
                        "borderColor": self.colors["High"],
                        "borderWidth": 1,
                        "stack": "violations",
                    },
                    {
                        "label": "Medium",
                        "data": medium_data,
                        "backgroundColor": self.colors["Medium"],
                        "borderColor": self.colors["Medium"],
                        "borderWidth": 1,
                        "stack": "violations",
                    },
                    {
                        "label": "Low",
                        "data": low_data,
                        "backgroundColor": self.colors["Low"],
                        "borderColor": self.colors["Low"],
                        "borderWidth": 1,
                        "stack": "violations",
                    },
                    {
                        "label": "Info",
                        "data": info_data,
                        "backgroundColor": self.colors["Info"],
                        "borderColor": self.colors["Info"],
                        "borderWidth": 1,
                        "stack": "violations",
                    },
                ],
            },
            "options": {
                "indexAxis": "y",
                "responsive": True,
                "maintainAspectRatio": False,
                "scales": {
                    "x": {
                        "stacked": True,
                        "beginAtZero": True,
                        "title": {"display": True, "text": "Number of Violations"},
                    },
                    "y": {
                        "stacked": True,
                        "title": {"display": True, "text": "Compliance Frameworks"},
                    },
                },
                "plugins": {
                    "legend": {"position": "top", "display": True},
                    "tooltip": {"mode": "index", "intersect": False},
                },
                "interaction": {"mode": "index", "intersect": False},
            },
        }

        return json.dumps(config)

    def create_top_checks_chart(self, top_checks: List[Dict[str, Any]]) -> str:
        """Create top failing checks chart.

        Args:
            top_checks: List of top failing security checks

        Returns:
            Chart.js configuration as JSON string
        """
        if not top_checks:
            return self._empty_chart_config()

        # Limit to top 10 for readability
        top_10_checks = top_checks[:10]

        # Use full labels but with smart truncation for very long titles
        labels = []
        for check in top_10_checks:
            title = check["check_title"]
            # Smart truncation: keep meaningful parts and break at word boundaries
            if len(title) > 60:
                # Find a good break point around 50-60 characters
                words = title.split()
                truncated = ""
                for word in words:
                    if len(truncated + word) <= 55:
                        truncated += word + " "
                    else:
                        break
                labels.append(truncated.strip() + "...")
            else:
                labels.append(title)

        failure_counts = [check["failure_count"] for check in top_10_checks]

        # Color by severity
        colors = [
            self.colors.get(check["severity"], "#6c757d") for check in top_10_checks
        ]

        # Store full check information for tooltips
        full_check_titles = [check["check_title"] for check in top_10_checks]
        check_ids = [check.get("check_id", "N/A") for check in top_10_checks]
        services = [check.get("service", "N/A") for check in top_10_checks]
        severities = [check["severity"] for check in top_10_checks]

        config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Failure Count",
                        "data": failure_counts,
                        "backgroundColor": colors,
                        "borderWidth": 1,
                        "fullTitles": full_check_titles,
                        "checkIds": check_ids,
                        "services": services,
                        "severities": severities,
                    }
                ],
            },
            "options": {
                "indexAxis": "y",
                "responsive": True,
                "maintainAspectRatio": False,
                "layout": {
                    "padding": {"left": 20, "right": 20, "top": 10, "bottom": 10}
                },
                "scales": {
                    "x": {
                        "beginAtZero": True,
                        "title": {"display": True, "text": "Number of Failures"},
                    },
                    "y": {
                        "title": {"display": True, "text": "Security Checks"},
                        "ticks": {"maxRotation": 0, "font": {"size": 11}},
                    },
                },
                "plugins": {
                    "legend": {"display": False},
                    "tooltip": {"mode": "nearest", "intersect": True},
                },
            },
        }

        return json.dumps(config)

    def _empty_chart_config(self) -> str:
        """Return empty chart configuration."""
        config = {
            "type": "pie",
            "data": {
                "labels": ["No Data"],
                "datasets": [
                    {
                        "data": [1],
                        "backgroundColor": ["#6c757d"],
                        "borderWidth": 2,
                        "borderColor": "#fff",
                    }
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "plugins": {
                    "legend": {"position": "bottom"},
                    "tooltip": {"mode": "nearest", "intersect": True},
                },
            },
            "layout": {"padding": 10},
        }
        return json.dumps(config)

    def create_compliance_dashboard(self, compliance_data: Dict) -> str:
        """Create compliance dashboard chart."""
        return self.create_compliance_chart(compliance_data)

    def create_compliance_chart(self, compliance_data: Dict) -> str:
        """Create compliance chart."""
        return json.dumps(
            {
                "type": "doughnut",
                "data": {
                    "labels": ["Compliant", "Non-Compliant"],
                    "datasets": [{"data": [80, 20]}],
                },
                "options": {"responsive": True},
            }
        )

    def create_regional_distribution_chart(
        self, regional_data: List[Dict[str, Any]]
    ) -> str:
        """Create regional distribution chart showing findings by region with severity breakdown.

        Args:
            regional_data: List of regional analysis data

        Returns:
            Chart.js configuration as JSON string
        """
        if not regional_data:
            return self._empty_chart_config()

        # Limit to top 15 regions for readability
        top_regions = regional_data[:15]

        labels = [region["region"] for region in top_regions]
        critical_data = [region["critical_failures"] for region in top_regions]
        high_data = [region["high_failures"] for region in top_regions]
        medium_data = [region["medium_failures"] for region in top_regions]
        low_data = [region["low_failures"] for region in top_regions]

        config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [
                    {
                        "label": "Critical",
                        "data": critical_data,
                        "backgroundColor": self.colors["Critical"],
                        "borderColor": self.colors["Critical"],
                        "borderWidth": 1,
                        "stack": "failures",
                    },
                    {
                        "label": "High",
                        "data": high_data,
                        "backgroundColor": self.colors["High"],
                        "borderColor": self.colors["High"],
                        "borderWidth": 1,
                        "stack": "failures",
                    },
                    {
                        "label": "Medium",
                        "data": medium_data,
                        "backgroundColor": self.colors["Medium"],
                        "borderColor": self.colors["Medium"],
                        "borderWidth": 1,
                        "stack": "failures",
                    },
                    {
                        "label": "Low",
                        "data": low_data,
                        "backgroundColor": self.colors["Low"],
                        "borderColor": self.colors["Low"],
                        "borderWidth": 1,
                        "stack": "failures",
                    },
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "interaction": {"mode": "index", "intersect": False},
                "scales": {
                    "x": {
                        "display": True,
                        "stacked": True,
                        "title": {"display": True, "text": "Regions"},
                        "ticks": {"maxRotation": 45, "minRotation": 45},
                    },
                    "y": {
                        "type": "linear",
                        "display": True,
                        "stacked": True,
                        "position": "left",
                        "title": {"display": True, "text": "Number of Failed Findings"},
                        "beginAtZero": True,
                    },
                },
                "plugins": {
                    "legend": {"position": "top"},
                    "tooltip": {
                        "mode": "index",
                        "intersect": False,
                        "callbacks": {
                            "afterLabel": "function(context) { const regionIndex = context.dataIndex; const regionData = "
                            + json.dumps(top_regions)
                            + "[regionIndex]; return [`Total Findings: ${regionData.total_findings}`, `Pass Rate: ${regionData.pass_rate}%`, `Accounts: ${regionData.unique_accounts}`, `Risk Score: ${regionData.risk_score}`]; }"
                        },
                    },
                },
            },
        }

        return json.dumps(config)

    # DISABLED: Heat map functionality temporarily disabled
    # def create_risk_heat_map_chart(self, heat_map_data: Dict[str, Any]) -> str:
    #     """Create risk heat map chart showing risk by service and account.
    #
    #     Args:
    #         heat_map_data: Heat map analysis data
    #
    #     Returns:
    #         Chart.js configuration as JSON string
    #     """
    #     if not heat_map_data or not heat_map_data.get('risk_matrix'):
    #         return self._empty_chart_config()
    #
    #     services = heat_map_data['services']
    #     accounts = heat_map_data['accounts']
    #     risk_matrix = heat_map_data['risk_matrix']
    #     max_risk = heat_map_data['max_risk']
    #
    #     # Limit to top 10 services and accounts for readability
    #     services = services[:10]
    #     accounts = accounts[:10]
    #
    #     # Prepare data for Chart.js heat map (using scatter plot with sized points)
    #     datasets = []
    #
    #     # Create data points for each service-account combination
    #     data_points = []
    #     colors = []
    #     sizes = []
    #
    #     for service_idx, service in enumerate(services):
    #         if service_idx < len(risk_matrix):
    #             service_row = risk_matrix[service_idx]
    #             for account_idx, account in enumerate(accounts):
    #                 if account_idx < len(service_row):
    #                     cell_data = service_row[account_idx]
    #                     risk_score = cell_data['risk_score']
    #                     finding_count = cell_data['finding_count']
    #
    #                     # Add data point
    #                     data_points.append({
    #                         'x': account_idx,
    #                         'y': service_idx,
    #                         'risk_score': risk_score,
    #                         'finding_count': finding_count,
    #                         'total_findings': cell_data['total_findings'],
    #                         'service': service,
    #                         'account': account['name']
    #                     })
    #
    #                     # Color based on risk level
    #                     if risk_score >= 70:
    #                         colors.append(self.colors['Critical'])
    #                     elif risk_score >= 40:
    #                         colors.append(self.colors['High'])
    #                     elif risk_score >= 20:
    #                         colors.append(self.colors['Medium'])
    #                     elif risk_score > 0:
    #                         colors.append(self.colors['Low'])
    #                     else:
    #                         colors.append('#f8f9fa')  # Light gray for no risk
    #
    #                     # Size based on finding count (min 5, max 25)
    #                     size = max(5, min(25, 5 + (finding_count / 10) * 20)) if finding_count > 0 else 5
    #                     sizes.append(size)
    #
    #     # Store metadata for JavaScript access
    #     chart_metadata = {
    #         'services': services,
    #         'accounts': [acc['name'] for acc in accounts],
    #         'dataPoints': data_points
    #     }
    #
    #     config = {
    #         'type': 'scatter',
    #         'data': {
    #             'datasets': [{
    #                 'label': 'Risk Level',
    #                 'data': [{'x': point['x'], 'y': point['y']} for point in data_points],
    #                 'backgroundColor': colors,
    #                 'borderColor': colors,
    #                 'borderWidth': 1,
    #                 'pointRadius': sizes,
    #                 'pointHoverRadius': [s + 3 for s in sizes]
    #             }]
    #         },
    #         'options': {
    #             'responsive': True,
    #             'maintainAspectRatio': False,
    #             'scales': {
    #                 'x': {
    #                     'type': 'linear',
    #                     'position': 'bottom',
    #                     'min': -0.5,
    #                     'max': len(accounts) - 0.5,
    #                     'ticks': {
    #                         'stepSize': 1
    #                     },
    #                     'title': {
    #                         'display': True,
    #                         'text': 'AWS Accounts'
    #                     }
    #                 },
    #                 'y': {
    #                     'type': 'linear',
    #                     'min': -0.5,
    #                     'max': len(services) - 0.5,
    #                     'ticks': {
    #                         'stepSize': 1
    #                     },
    #                     'title': {
    #                         'display': True,
    #                         'text': 'AWS Services'
    #                     }
    #                 }
    #             },
    #             'plugins': {
    #                 'legend': {
    #                     'display': False
    #                 },
    #                 'tooltip': {
    #                     'mode': 'nearest',
    #                     'intersect': True
    #                 }
    #             },
    #             'interaction': {
    #                 'intersect': True,
    #                 'mode': 'point'
    #             }
    #         },
    #         'metadata': chart_metadata
    #     }
    #
    #     return json.dumps(config)

    def create_improvement_roadmap_chart(self, roadmap_data: Dict[str, Any]) -> str:
        """Create improvement roadmap chart showing timeline and effort distribution.

        Args:
            roadmap_data: Roadmap analysis data

        Returns:
            Chart.js configuration as JSON string
        """
        if not roadmap_data or not roadmap_data.get("summary", {}).get("total_issues"):
            return self._empty_chart_config()

        # Prepare data for timeline chart
        categories = [
            "Immediate\n(1-2 weeks)",
            "Short Term\n(1-2 months)",
            "Long Term\n(3-6 months)",
        ]
        issue_counts = [
            roadmap_data["immediate"]["count"],
            roadmap_data["short_term"]["count"],
            roadmap_data["long_term"]["count"],
        ]
        effort_weeks = [
            roadmap_data["immediate"]["effort_weeks"],
            roadmap_data["short_term"]["effort_weeks"],
            roadmap_data["long_term"]["effort_weeks"],
        ]

        # Color coding for urgency
        colors = ["#dc3545", "#fd7e14", "#28a745"]  # Red, Orange, Green
        border_colors = ["#c82333", "#e0a800", "#1e7e34"]

        config = {
            "type": "bar",
            "data": {
                "labels": categories,
                "datasets": [
                    {
                        "label": "Number of Issues",
                        "data": issue_counts,
                        "backgroundColor": [
                            f"{color}80" for color in colors
                        ],  # Add transparency
                        "borderColor": border_colors,
                        "borderWidth": 2,
                        "yAxisID": "y",
                    },
                    {
                        "label": "Effort (Weeks)",
                        "data": effort_weeks,
                        "backgroundColor": "rgba(54, 162, 235, 0.6)",
                        "borderColor": "rgba(54, 162, 235, 1)",
                        "borderWidth": 2,
                        "type": "line",
                        "yAxisID": "y1",
                        "tension": 0.4,
                        "pointRadius": 6,
                        "pointHoverRadius": 8,
                    },
                ],
            },
            "options": {
                "responsive": True,
                "maintainAspectRatio": False,
                "interaction": {"mode": "index", "intersect": False},
                "scales": {
                    "x": {
                        "display": True,
                        "title": {"display": True, "text": "Implementation Timeline"},
                        "ticks": {"maxRotation": 0, "minRotation": 0},
                    },
                    "y": {
                        "type": "linear",
                        "display": True,
                        "position": "left",
                        "title": {"display": True, "text": "Number of Issues"},
                        "beginAtZero": True,
                    },
                    "y1": {
                        "type": "linear",
                        "display": True,
                        "position": "right",
                        "title": {"display": True, "text": "Effort Required (Weeks)"},
                        "beginAtZero": True,
                        "grid": {"drawOnChartArea": False},
                    },
                },
                "plugins": {
                    "legend": {"position": "top"},
                    "tooltip": {
                        "mode": "index",
                        "intersect": False,
                        "callbacks": {
                            "afterLabel": "function(context) { const index = context.dataIndex; const roadmapData = "
                            + json.dumps(roadmap_data)
                            + '; const categories = ["immediate", "short_term", "long_term"]; const category = categories[index]; const data = roadmapData[category]; return [`Timeline: ${data.timeline}`, `Description: ${data.description}`]; }'
                        },
                    },
                },
            },
        }

        return json.dumps(config)

    def generate_all_charts(self, analytics_results: Dict) -> Dict[str, str]:
        """Generate all charts from analytics results."""
        charts = {}

        if "severity_distribution" in analytics_results:
            charts["severity"] = self.create_severity_distribution_chart(
                analytics_results["severity_distribution"]
            )

        if "account_analysis" in analytics_results:
            charts["accounts"] = self.create_account_comparison_chart(
                analytics_results["account_analysis"]
            )

        return charts

    @property
    def severity_colors(self) -> Dict[str, str]:
        """Get severity color mapping."""
        return {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Info": "#17a2b8",
        }
