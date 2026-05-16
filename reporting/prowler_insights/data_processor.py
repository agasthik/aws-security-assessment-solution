#!/usr/bin/env python3
"""
Data Processor Module - Data cleaning and normalization for security findings.
"""

import pandas as pd
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class DataProcessor:
    """Handles data cleaning and normalization of security findings."""

    def __init__(self):
        """Initialize the data processor."""
        self.severity_mapping = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Info',
            'INFORMATIONAL': 'Info'
        }

        self.status_mapping = {
            'FAIL': 'Failed',
            'PASS': 'Passed',
            'MANUAL': 'Manual',
            'INFO': 'Info'
        }

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize the security findings data.

        Args:
            df: Raw security findings DataFrame

        Returns:
            Cleaned DataFrame
        """
        if df.empty:
            logger.warning("Empty DataFrame provided for cleaning")
            return df

        logger.info(f"Starting data cleaning for {len(df)} findings")

        # Create a copy to avoid modifying original
        cleaned_df = df.copy()

        # Normalize severity values
        if 'SEVERITY' in cleaned_df.columns:
            cleaned_df['SEVERITY'] = cleaned_df['SEVERITY'].str.upper()
            cleaned_df['SEVERITY'] = cleaned_df['SEVERITY'].map(self.severity_mapping).fillna(cleaned_df['SEVERITY'])

        # Normalize status values
        if 'STATUS' in cleaned_df.columns:
            cleaned_df['STATUS'] = cleaned_df['STATUS'].str.upper()
            cleaned_df['STATUS'] = cleaned_df['STATUS'].map(self.status_mapping).fillna(cleaned_df['STATUS'])

        # Clean account names
        if 'ACCOUNT_NAME' in cleaned_df.columns:
            cleaned_df['ACCOUNT_NAME'] = cleaned_df['ACCOUNT_NAME'].fillna('Unknown Account')
        elif 'ACCOUNT_UID' in cleaned_df.columns:
            cleaned_df['ACCOUNT_NAME'] = cleaned_df['ACCOUNT_UID'].astype(str)

        # Clean service names
        if 'SERVICE_NAME' in cleaned_df.columns:
            cleaned_df['SERVICE_NAME'] = cleaned_df['SERVICE_NAME'].fillna('Unknown Service')

        # Clean regions
        if 'REGION' in cleaned_df.columns:
            cleaned_df['REGION'] = cleaned_df['REGION'].fillna('Unknown Region')

        # Clean check titles
        if 'CHECK_TITLE' in cleaned_df.columns:
            cleaned_df['CHECK_TITLE'] = cleaned_df['CHECK_TITLE'].fillna('Unknown Check')
        elif 'CHECK_ID' in cleaned_df.columns:
            cleaned_df['CHECK_TITLE'] = cleaned_df['CHECK_ID'].astype(str)

        # Parse compliance frameworks
        if 'COMPLIANCE' in cleaned_df.columns:
            cleaned_df['COMPLIANCE_FRAMEWORKS'] = cleaned_df['COMPLIANCE'].apply(self._parse_compliance)
        else:
            cleaned_df['COMPLIANCE_FRAMEWORKS'] = ''

        # Remove duplicates based on key fields
        key_columns = ['FINDING_UID'] if 'FINDING_UID' in cleaned_df.columns else ['ACCOUNT_UID', 'CHECK_ID', 'REGION']
        initial_count = len(cleaned_df)
        cleaned_df = cleaned_df.drop_duplicates(subset=key_columns, keep='first')
        duplicates_removed = initial_count - len(cleaned_df)

        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate findings")

        logger.info(f"Data cleaning completed: {len(cleaned_df)} findings remaining")
        return cleaned_df

    def _parse_compliance(self, compliance_str: str) -> str:
        """Parse compliance framework information.

        Args:
            compliance_str: Raw compliance string

        Returns:
            Cleaned compliance frameworks string
        """
        if pd.isna(compliance_str) or not compliance_str:
            return ''

        # Extract common compliance frameworks
        frameworks = []
        compliance_upper = str(compliance_str).upper()

        if 'CIS' in compliance_upper:
            frameworks.append('CIS')
        if 'ISO27001' in compliance_upper or 'ISO 27001' in compliance_upper:
            frameworks.append('ISO27001')
        if 'SOC2' in compliance_upper or 'SOC 2' in compliance_upper:
            frameworks.append('SOC2')
        if 'PCI' in compliance_upper:
            frameworks.append('PCI-DSS')
        if 'GDPR' in compliance_upper:
            frameworks.append('GDPR')
        if 'HIPAA' in compliance_upper:
            frameworks.append('HIPAA')

        return ', '.join(frameworks) if frameworks else 'Other'

    def calculate_security_score(self, df: pd.DataFrame) -> Dict[str, float]:
        """Calculate security scores based on findings.

        Args:
            df: Processed security findings DataFrame

        Returns:
            Dictionary with security scores
        """
        if df.empty:
            return {'overall_score': 0.0, 'account_scores': {}}

        # Weight different severities
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }

        # Calculate overall score
        total_findings = len(df)
        failed_findings = len(df[df['STATUS'] == 'Failed']) if 'STATUS' in df.columns else 0

        if total_findings == 0:
            overall_score = 100.0
        else:
            # Calculate weighted penalty
            penalty = 0
            for severity, weight in severity_weights.items():
                severity_fails = len(df[(df['STATUS'] == 'Failed') & (df['SEVERITY'] == severity)])
                penalty += severity_fails * weight

            # Normalize to 0-100 scale
            max_possible_penalty = total_findings * severity_weights['Critical']
            overall_score = max(0, 100 - (penalty / max_possible_penalty * 100)) if max_possible_penalty > 0 else 100

        # Calculate per-account scores
        account_scores = {}
        if 'ACCOUNT_UID' in df.columns:
            for account in df['ACCOUNT_UID'].unique():
                account_df = df[df['ACCOUNT_UID'] == account]
                account_total = len(account_df)
                account_failed = len(account_df[account_df['STATUS'] == 'Failed']) if 'STATUS' in account_df.columns else 0

                if account_total == 0:
                    account_scores[account] = 100.0
                else:
                    account_penalty = 0
                    for severity, weight in severity_weights.items():
                        severity_fails = len(account_df[(account_df['STATUS'] == 'Failed') & (account_df['SEVERITY'] == severity)])
                        account_penalty += severity_fails * weight

                    max_account_penalty = account_total * severity_weights['Critical']
                    account_scores[account] = max(0, 100 - (account_penalty / max_account_penalty * 100)) if max_account_penalty > 0 else 100

        return {
            'overall_score': round(overall_score, 1),
            'account_scores': {k: round(v, 1) for k, v in account_scores.items()}
        }
    def process_data(self, df: pd.DataFrame) -> tuple:
        """Process data and return cleaned DataFrame with statistics.

        Args:
            df: Raw DataFrame to process

        Returns:
            Tuple of (cleaned_df, statistics_dict)
        """
        cleaned_df = self.clean_data(df)

        stats = {
            'original_rows': len(df),
            'cleaned_rows': len(cleaned_df),
            'columns_processed': len(cleaned_df.columns) if not cleaned_df.empty else 0
        }

        return cleaned_df, stats

