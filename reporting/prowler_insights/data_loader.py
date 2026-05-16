#!/usr/bin/env python3
"""
Data Loader Module - CSV file discovery and loading for Prowler security scan data.
Supports both local filesystem and S3 paths.
"""

import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Union

logger = logging.getLogger(__name__)


class DataLoader:
    """Handles discovery and loading of Prowler CSV files from local or S3."""

    # Encodings to try when loading CSV files
    SUPPORTED_ENCODINGS = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]

    def __init__(self, output_directory: str = "output"):
        """Initialize the data loader.

        Args:
            output_directory: Directory containing Prowler CSV files.
                              Can be a local path or S3 URI (s3://bucket/prefix)
        """
        self._output_directory = output_directory
        self._is_s3 = output_directory.startswith("s3://")

        if not self._is_s3:
            self.output_dir = Path(output_directory)
        else:
            self.output_dir = None

        self.supported_encodings = list(self.SUPPORTED_ENCODINGS)

        self.required_columns = [
            "FINDING_UID",
            "ACCOUNT_UID",
            "CHECK_ID",
            "STATUS",
            "SEVERITY",
            "SERVICE_NAME",
            "REGION",
        ]

    @property
    def output_directory(self) -> str:
        """The output directory path as a string."""
        return self._output_directory

    def _discover_s3_csv_files(self) -> List[str]:
        """Discover CSV files in an S3 location.

        Returns:
            List of S3 URIs for CSV files
        """
        try:
            import boto3

            # Parse S3 URI
            s3_path = self._output_directory[5:]  # Remove 's3://'
            bucket = s3_path.split("/")[0]
            prefix = "/".join(s3_path.split("/")[1:])
            if prefix and not prefix.endswith("/"):
                prefix += "/"

            s3 = boto3.client("s3")
            csv_files = []

            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".csv"):
                        csv_files.append(f"s3://{bucket}/{key}")

            logger.info(f"Discovered {len(csv_files)} CSV files in S3")
            return csv_files

        except Exception as e:
            logger.error(f"Failed to list S3 objects: {e}")
            return []

    def discover_csv_files(self) -> List[Union[Path, str]]:
        """Discover CSV files in the output directory.

        Returns:
            List of CSV file paths (Path objects for local, strings for S3)
        """
        if self._is_s3:
            return self._discover_s3_csv_files()

        if not self.output_dir.exists():
            logger.warning(f"Output directory does not exist: {self.output_dir}")
            return []

        csv_files = []
        patterns = ["*.csv", "*prowler*.csv", "*security*.csv"]

        for pattern in patterns:
            csv_files.extend(self.output_dir.glob(pattern))

        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for file in csv_files:
            if file not in seen:
                seen.add(file)
                unique_files.append(file)

        logger.info(f"Discovered {len(unique_files)} CSV files")
        return unique_files

    def load_csv_file(self, file_path: Union[Path, str]) -> Optional[pd.DataFrame]:
        """Load a single CSV file from local filesystem or S3.

        Args:
            file_path: Path to the CSV file (local Path or S3 URI string)

        Returns:
            DataFrame or None if loading failed
        """
        try:
            logger.debug(f"Loading CSV file: {file_path}")

            # pandas can read S3 URIs directly with s3fs installed
            df = pd.read_csv(file_path, sep=";", low_memory=False)

            if df.empty:
                logger.warning(f"Empty CSV file: {file_path}")
                return None

            # Normalize column names to uppercase
            df.columns = df.columns.str.upper()

            # Check for required columns
            missing_cols = [
                col for col in self.required_columns if col not in df.columns
            ]
            if missing_cols:
                logger.warning(
                    f"Missing required columns in {file_path}: {missing_cols}"
                )

            logger.info(f"Loaded {len(df)} rows from {file_path}")
            return df

        except Exception as e:
            logger.error(f"Failed to load CSV file {file_path}: {e}")
            return None

    def _get_filename(self, file_path: Union[Path, str]) -> str:
        """Extract filename from a local path or S3 URI."""
        if isinstance(file_path, Path):
            return file_path.name
        # S3 URI
        return file_path.split("/")[-1]

    def load_all_data(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Load and combine all CSV files.

        Returns:
            Tuple of (Combined DataFrame with all security findings, loading statistics)
        """
        csv_files = self.discover_csv_files()

        if not csv_files:
            logger.error(f"No CSV files found in: {self._output_directory}")
            return pd.DataFrame(), {
                "files_loaded": 0,
                "total_files": 0,
                "files_found": 0,
                "total_findings": 0,
                "total_rows": 0,
            }

        dataframes = []
        for file_path in csv_files:
            df = self.load_csv_file(file_path)
            if df is not None:
                df["SOURCE_FILE"] = self._get_filename(file_path)
                dataframes.append(df)

        if not dataframes:
            logger.error("No valid CSV files could be loaded")
            return pd.DataFrame(), {
                "files_loaded": 0,
                "total_files": len(csv_files),
                "files_found": len(csv_files),
                "total_findings": 0,
                "total_rows": 0,
            }

        combined_df = pd.concat(dataframes, ignore_index=True)
        logger.info(
            f"Combined data: {len(combined_df)} total findings from {len(dataframes)} files"
        )

        # Detect cloud providers present in the data
        providers = []
        if "PROVIDER" in combined_df.columns:
            providers = sorted(
                combined_df["PROVIDER"].dropna().str.lower().unique().tolist()
            )
        if not providers:
            providers = ["aws"]

        stats = {
            "files_loaded": len(dataframes),
            "total_files": len(csv_files),
            "files_found": len(csv_files),
            "total_findings": len(combined_df),
            "total_rows": len(combined_df),
            "providers": providers,
        }

        logger.info(f"Detected cloud providers: {', '.join(providers)}")
        return combined_df, stats
