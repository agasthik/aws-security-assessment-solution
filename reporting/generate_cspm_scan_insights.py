#!/usr/bin/env python3
"""
Main Dashboard Generator - Orchestrates the complete security dashboard generation process.
"""

import argparse
import logging
import sys
from pathlib import Path

from prowler_insights.data_loader import DataLoader
from prowler_insights.data_processor import DataProcessor
from prowler_insights.analytics import SecurityAnalytics
from prowler_insights.visualizations import ChartGenerator
from prowler_insights.report_builder import ReportBuilder


def setup_logging(log_level: str = "INFO") -> None:
    """Set up logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logger = logging.getLogger(__name__)
    logger.info("Logging initialized")


def main():
    """Main dashboard generation function."""
    parser = argparse.ArgumentParser(
        description="Generate CSPM Security Insights Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Basic usage with defaults
  %(prog)s --output-dir ./scans               # Custom input directory
  %(prog)s --dashboard-file my_report.html    # Custom output filename
  %(prog)s --log-level DEBUG                  # Enable debug logging
  %(prog)s --company-name "Acme Corp"         # Include company name in header
        """,
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory containing Prowler CSV files (default: output)",
    )

    parser.add_argument(
        "--dashboard-file",
        default="cspm_scan_insights.html",
        help="Output filename for dashboard (default: cspm_scan_insights.html)",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    parser.add_argument(
        "--company-name", help="Company name to display in dashboard header (optional)"
    )

    args = parser.parse_args()

    # Set up logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        logger.info("Starting CSPM Security Dashboard Generation")
        logger.info(f"Input directory: {args.output_dir}")
        logger.info(f"Output file: {args.dashboard_file}")

        # Step 1: Load data
        logger.info("Step 1: Loading security findings data...")
        data_loader = DataLoader(args.output_dir)
        raw_data, load_stats = data_loader.load_all_data()

        if raw_data.empty:
            logger.error("No data loaded. Please check your CSV files and try again.")
            sys.exit(1)

        logger.info(
            f"Loaded {len(raw_data)} security findings from {load_stats['files_loaded']} files"
        )

        # Detect providers from loaded data
        providers = load_stats.get("providers", ["aws"])

        # Step 2: Process data
        logger.info("Step 2: Processing and cleaning data...")
        data_processor = DataProcessor()
        processed_data = data_processor.clean_data(raw_data)
        security_scores = data_processor.calculate_security_score(processed_data)

        logger.info(
            f"Data processing completed. Overall security score: {security_scores['overall_score']}%"
        )

        # Step 3: Generate analytics
        logger.info("Step 3: Generating security analytics...")
        analytics = SecurityAnalytics()

        summary_stats = analytics.generate_summary_stats(processed_data)
        summary_stats["overall_score"] = security_scores["overall_score"]
        summary_stats["providers"] = providers

        account_analysis = analytics.analyze_account_security_posture(processed_data)
        service_analysis = analytics.analyze_service_vulnerabilities(processed_data)
        compliance_analysis = analytics.analyze_compliance_gaps(processed_data)
        top_checks = analytics.analyze_top_failing_checks(processed_data)
        regional_analysis = analytics.analyze_regional_distribution(processed_data)
        roadmap_data = analytics.analyze_improvement_roadmap(processed_data)

        logger.info("Security analytics generated")

        # Step 4: Create visualizations
        logger.info("Step 4: Creating interactive charts...")
        chart_generator = ChartGenerator()

        chart_configs = {
            "severity_chart": chart_generator.create_severity_distribution_chart(
                summary_stats.get("failed_by_severity", {})
            ),
            "account_chart": chart_generator.create_account_comparison_chart(
                account_analysis
            ),
            "service_chart": chart_generator.create_service_risk_chart(
                service_analysis
            ),
            "checks_chart": chart_generator.create_top_checks_chart(top_checks),
            "regions_chart": chart_generator.create_regional_distribution_chart(
                regional_analysis
            ),
            "roadmap_chart": chart_generator.create_improvement_roadmap_chart(
                roadmap_data
            ),
        }

        # Add compliance chart if data available
        if compliance_analysis.get("frameworks"):
            chart_configs["compliance_chart"] = chart_generator.create_compliance_chart(
                compliance_analysis
            )

        logger.info("Interactive charts created")

        # Step 5: Build HTML report
        logger.info("Step 5: Building HTML dashboard...")
        report_builder = ReportBuilder()

        html_dashboard = report_builder.build_dashboard(
            summary_stats=summary_stats,
            account_analysis=account_analysis,
            service_analysis=service_analysis,
            compliance_analysis=compliance_analysis,
            top_checks=top_checks,
            chart_configs=chart_configs,
            company_name=args.company_name,
            regional_analysis=regional_analysis,
            roadmap_data=roadmap_data,
        )

        # Step 6: Save dashboard
        logger.info(f"Step 6: Saving dashboard to {args.dashboard_file}...")

        with open(args.dashboard_file, "w", encoding="utf-8") as f:
            f.write(html_dashboard)

        file_size = Path(args.dashboard_file).stat().st_size / (1024 * 1024)  # MB
        logger.info(f"Dashboard saved successfully ({file_size:.1f} MB)")

        # Summary
        providers_str = ", ".join(p.upper() for p in providers)
        logger.info("Dashboard Generation Complete!")
        logger.info("=" * 50)
        logger.info(f"Dashboard file: {args.dashboard_file}")
        logger.info(f"Cloud providers: {providers_str}")
        logger.info(f"Total findings: {summary_stats['total_findings']}")
        logger.info(f"Accounts/subscriptions: {summary_stats['unique_accounts']}")
        logger.info(f"Critical findings: {summary_stats['critical_findings']}")
        logger.info(f"High findings: {summary_stats['high_findings']}")
        logger.info(f"Security score: {security_scores['overall_score']}%")

        logger.info("=" * 50)
        logger.info(f"Open the dashboard: open {args.dashboard_file}")

    except KeyboardInterrupt:
        logger.info("Dashboard generation interrupted by user")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Dashboard generation failed: {e}")
        logger.debug("Full error details:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
