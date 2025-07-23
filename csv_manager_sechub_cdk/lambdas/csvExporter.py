#!/usr/local/bin/python3
"""
Convert SecurityHub findings to CSV and store in an S3 bucket

This program can be invoked as an AWS Lambda function or from the command line.
If invoked from the command line, an assumable role is required. If invoked
from Lambda no parameters are required.

python3 csvExporter.py 
       --role-arn=[assumeableRoleArn] 
       --regions=[commaSeaparatedRegionList]
       --bucket=[s3BucketName]
       --filters=[cannedFilterName|jsonObject]
"""

import json
import argparse
import csv
import sys
import os
import csvObjects as csvo
import logging
import traceback
import re
import boto3
import uuid
import time
from datetime import datetime

# Default regions in list and string form
_DEFAULT_REGION_STRING = ""
_DEFAULT_REGION_LIST = [] #_DEFAULT_REGION_STRING.split(",")

# Retrieves the name of the current function (for logging purposes)
this = lambda frame=0 : sys._getframe(frame+1).f_code.co_name

_DEFAULT_LOGGING_LEVEL = logging.INFO
""" Default logging level """

# Set up logging
logging.basicConfig(level=_DEFAULT_LOGGING_LEVEL)

# Retrieve the logging instance
_LOGGER = logging.getLogger()
_LOGGER.setLevel(_DEFAULT_LOGGING_LEVEL)
""" Initialized logging RootLogger instance """

################################################################################
#### 
################################################################################
def choose (default=None, *choices):
    """
    Choose between an option and an environment variable (the option always
    has priority, if specified)
    """
    answer = default

    for choice in choices:
        _LOGGER.debug(f'csvExport.493010i choice {choice}')

        if choice:
            answer = choice
            break

    return answer
################################################################################
#### 
################################################################################
def getFilters ( candidate = None ):
    """
    Process filters, which are specified as a JSON object or as a string, in 
    this case "HighActive." If the filter can't be parsed, a messagae is issued
    but a null filter is returned. 
    """
    if not candidate:
        filters = {}
    elif candidate != "HighActive":
        try:
            if type(candidate) is dict:
                filters = candidate
            else:
                filters = json.loads(candidate)
        except Exception as thrown:
            _LOGGER.error(f'493020e filter parsing failed: {thrown}')
            filters = {}
    else:
        _LOGGER.info("493030i canned HighActive filter selects active high- " + \
            "and critical-severity findings")
        filters = {
            "SeverityLabel": 
            [ 
                {"Value": "CRITICAL", "Comparison": "EQUALS" }, 
                {"Value": "HIGH", "Comparison": "EQUALS"}
            ], 
            "RecordState": 
            [ 
                { "Comparison": "EQUALS", "Value": "ACTIVE"}
            ]
        }

    return filters

################################################################################
#### Pagination-aware executor for Step Function integration
################################################################################
def executor_with_pagination(role=None, region=None, filters=None, bucket=None, 
    limit=0, retain=False, next_token=None, task_token=None, batch_size=1000, execution_id=None):
    """
    Carry out the actions necessary to download and export SecurityHub findings
    with pagination support for Step Function integration.
    
    Args:
        role: IAM role ARN for AWS operations
        region: Primary AWS region
        filters: Security Hub filters to apply
        bucket: S3 bucket name for export
        limit: Maximum number of findings to process (0 = no limit)
        retain: Whether to retain local file after upload
        next_token: Pagination token to resume from previous call
        task_token: Step Function task token for callbacks
        batch_size: Number of findings to process per batch
        execution_id: Step Function execution ID for state management
    
    Returns:
        dict: Result with pagination info and export details
    """
    # Initialize error tracking and default answer
    error_context = {
        "function": "executor_with_pagination",
        "execution_id": execution_id,
        "batch_size": batch_size,
        "has_next_token": bool(next_token)
    }
    
    # Initialize default answer in case of early exit
    answer = {
        "success": False,
        "message": "Export failed - initialization error",
        "bucket": bucket,
        "exportKey": None,
        "hasMore": False,
        "nextToken": None,
        "processedCount": 0,
        "currentBatch": 0,
        "lastBatchSize": 0
    }
    
    try:
        # Get the SSM parameters and a client for further SSM operations
        ssmActor = csvo.SsmActor(role=role, region=region)
        
        # Load and validate pagination state if continuing from previous execution
        if next_token or execution_id:
            try:
                current_state = load_pagination_state(role=role, region=region)
                
                # Validate state consistency
                if execution_id:
                    is_valid, validation_error = validate_pagination_state(current_state, execution_id)
                    if not is_valid:
                        _LOGGER.warning(f"493340w Pagination state validation failed: {validation_error}")
                        # Reset corrupted state
                        current_state = reset_corrupted_state(role=role, region=region, execution_id=execution_id)
                        next_token = None  # Start fresh
                        
            except Exception as state_error:
                _LOGGER.error(f"493341e Error managing pagination state: {state_error}")
                # Continue with fresh state on error
                current_state = PaginationState(execution_id=execution_id or str(uuid.uuid4()))
                next_token = None
    
    except Exception as init_error:
        error_context["stage"] = "initialization"
        error_context["error"] = str(init_error)
        _LOGGER.error(f"493342e Initialization failed: {init_error}")
        raise RuntimeError(f"Failed to initialize executor: {init_error}") from init_error
    
    # Get a list of Security Hub regions we wish to act on
    regions = choose(
        os.environ.get("CSV_SECURITYHUB_REGIONLIST"),
        re.compile(r"\s*,\s*").split(getattr(ssmActor, "/csvManager/regionList", region)),
        ssmActor.getSupportedRegions(service="securityhub")
    )
    
    error_context["regions"] = regions
    
    _LOGGER.info("493040i selected SecurityHub regions %s" % regions)

    # Get information about the bucket with error handling
    try:
        folder = getattr(ssmActor, "/csvManager/folder/findings", None)
        bucket = bucket if bucket else getattr(ssmActor, "/csvManager/bucket", None)
        
        if not bucket:
            raise ValueError("S3 bucket not specified and not found in SSM parameters")
            
        _LOGGER.debug(f'493050d writing to s3://{bucket}/{folder}/*')
        
    except Exception as bucket_error:
        error_context["stage"] = "bucket_configuration"
        error_context["error"] = str(bucket_error)
        _LOGGER.error(f"493343e Failed to configure S3 bucket: {bucket_error}")
        raise RuntimeError(f"S3 bucket configuration failed: {bucket_error}") from bucket_error

    # Initialize S3 actor with error handling
    try:
        s3Actor = csvo.S3Actor(
            bucket=bucket, 
            folder=folder, 
            region=region, 
            role=role
        )
        localFile = s3Actor.filePath()
        
    except Exception as s3_error:
        error_context["stage"] = "s3_initialization"
        error_context["error"] = str(s3_error)
        _LOGGER.error(f"493344e Failed to initialize S3 actor: {s3_error}")
        raise RuntimeError(f"S3 actor initialization failed: {s3_error}") from s3_error

    # Initialize Security Hub actor with error handling
    try:
        hubActor = csvo.HubActor(
            role=role,
            region=regions
        )
        hubActor.set_batch_size(batch_size)
        
    except Exception as hub_error:
        error_context["stage"] = "hub_initialization"
        error_context["error"] = str(hub_error)
        _LOGGER.error(f"493345e Failed to initialize Security Hub actor: {hub_error}")
        raise RuntimeError(f"Security Hub actor initialization failed: {hub_error}") from hub_error

    # Download findings with comprehensive error handling
    try:
        error_context["stage"] = "findings_download"
        hubActor.downloadFindings(
            filters=filters,
            limit=limit,
            next_token=next_token,
            batch_size=batch_size
        )
            
    except Exception as download_error:
        error_context["error"] = str(download_error)
        _LOGGER.error(f"493346e Failed to download findings: {download_error}")
        
        # Try to save current state before failing
        if execution_id:
            try:
                current_state = PaginationState(
                    next_token=next_token or "",
                    execution_id=execution_id,
                    processed_count=getattr(hubActor, 'processed_count', 0)
                )
                save_pagination_state(current_state, role=role, region=region)
                _LOGGER.info("493347i Saved current state before failing")
            except Exception as save_error:
                _LOGGER.warning(f"493348w Failed to save state on error: {save_error}")
        
        raise RuntimeError(f"Findings download failed: {download_error}") from download_error

    # Process findings with error handling
    try:
        error_context["stage"] = "findings_processing"
        
        if hubActor.count <= 0:
            _LOGGER.warning("493060w no findings downloaded in this batch")
            
            # Return completion result if no findings and no more data
            if not hubActor.has_more_data:
                # Clean up state on completion
                if execution_id:
                    try:
                        cleanup_pagination_state(role=role, region=region)
                    except Exception as cleanup_error:
                        _LOGGER.warning(f"493349w Failed to cleanup state: {cleanup_error}")
                
                return {
                    "success": True,
                    "message": "Export completed - no findings found",
                    "bucket": bucket,
                    "exportKey": None,
                    "hasMore": False,
                    "nextToken": None,
                    "processedCount": hubActor.processed_count,
                    "currentBatch": hubActor.current_batch
                }
            else:
                # This shouldn't happen, but handle gracefully
                return {
                    "success": False,
                    "message": "No findings in batch but more data available",
                    "hasMore": hubActor.has_more_data,
                    "nextToken": hubActor.next_token,
                    "processedCount": hubActor.processed_count,
                    "currentBatch": hubActor.current_batch
                }
        else:
            _LOGGER.info(f'493070i preparing to write {hubActor.count} findings from batch {hubActor.current_batch}')

            first = True
            append_mode = next_token is not None  # Append if continuing from previous batch

            # Open file in append mode if continuing, write mode if starting fresh
            file_mode = 'a' if append_mode else 'w'
            
            # File writing with error handling
            try:
                with open(localFile, file_mode) as target:
                    for finding in hubActor.getFinding():
                        findingObject = csvo.Finding(finding, actor=hubActor)

                        # Start the CSV file with a header only for the first batch
                        if first and not append_mode:
                            _LOGGER.debug("493080d finding object %s keys %s" \
                                % (findingObject, findingObject.columns))

                            writer = csv.DictWriter(target, 
                                fieldnames=findingObject.columns)

                            writer.writeheader()
                        elif first and append_mode:
                            # For append mode, create writer without header
                            writer = csv.DictWriter(target, 
                                fieldnames=findingObject.columns)

                        # Write the finding
                        writer.writerow(findingObject.rowMap)
                        first = False

                # Announce completion of write
                _LOGGER.info("493090i findings written to %s" % localFile)
                
            except Exception as file_error:
                error_context["error"] = str(file_error)
                _LOGGER.error(f"493350e Failed to write findings to file: {file_error}")
                raise RuntimeError(f"File writing failed: {file_error}") from file_error

            # Get pagination info
            pagination_info = hubActor.get_pagination_info()
            progress_summary = hubActor.get_progress_summary()
            
            _LOGGER.info(f"493091i batch processing summary: {progress_summary}")

            # Save current state for continuation
            if execution_id:
                try:
                    current_state = PaginationState(
                        next_token=pagination_info["nextToken"] or "",
                        execution_id=execution_id,
                        processed_count=pagination_info["processedCount"]
                    )
                    save_pagination_state(current_state, role=role, region=region)
                except Exception as save_error:
                    _LOGGER.warning(f"493351w Failed to save pagination state: {save_error}")

            # Only upload to S3 if this is the final batch or if configured to upload each batch
            should_upload = not pagination_info["hasMore"]  # Upload only when complete
            
            if should_upload:
                try:
                    # Place the object in the S3 bucket
                    s3Actor.put()

                    _LOGGER.info('493100i uploaded to ' + 
                        f's3://{s3Actor.bucket}/{s3Actor.objectKey}')

                    # Determine whether to retain the local file or not
                    if retain:
                        _LOGGER.warning("493110w local file %s retained" % localFile)
                    else:
                        os.unlink(localFile)
                        _LOGGER.info("493120i local file deleted")

                    export_key = s3Actor.objectKey
                    
                    # Clean up state on successful completion
                    if execution_id and not pagination_info["hasMore"]:
                        try:
                            cleanup_pagination_state(role=role, region=region)
                        except Exception as cleanup_error:
                            _LOGGER.warning(f"493352w Failed to cleanup state: {cleanup_error}")
                            
                except Exception as upload_error:
                    error_context["error"] = str(upload_error)
                    _LOGGER.error(f"493353e Failed to upload to S3: {upload_error}")
                    raise RuntimeError(f"S3 upload failed: {upload_error}") from upload_error
            else:
                _LOGGER.info("493101i batch complete, continuing with next batch - file not uploaded yet")
                export_key = None

            # Return details to caller with pagination information
            answer = {
                "success": True,
                "message": f"Batch {pagination_info['currentBatch']} processed successfully",
                "bucket": bucket,
                "exportKey": export_key,
                "hasMore": pagination_info["hasMore"],
                "nextToken": pagination_info["nextToken"],
                "processedCount": pagination_info["processedCount"],
                "currentBatch": pagination_info["currentBatch"],
                "lastBatchSize": pagination_info["lastBatchSize"]
            }

    except Exception as processing_error:
        error_context["error"] = str(processing_error)
        _LOGGER.error(f"493354e Processing failed: {processing_error}")
        raise

    except Exception as executor_error:
        # Log comprehensive error information
        _LOGGER.error(f"493355e Executor failed at stage {error_context.get('stage', 'unknown')}: {executor_error}")
        _LOGGER.error(f"493356e Error context: {json.dumps(error_context, indent=2)}")
        
        # Try to save error state for recovery
        if execution_id:
            try:
                error_state = PaginationState(
                    next_token=next_token or "",
                    execution_id=execution_id,
                    processed_count=0  # Reset on error
                )
                save_pagination_state(error_state, role=role, region=region)
                _LOGGER.info("493357i Saved error state for potential recovery")
            except Exception as save_error:
                _LOGGER.warning(f"493358w Failed to save error state: {save_error}")
        
        # Re-raise the error for Step Function handling
        raise

    return answer

################################################################################
#### Invocation-independent process handler
################################################################################
def executor (role=None, region=None, filters=None, bucket=None, limit=0, 
    retain=False):
    """
    Carry out the actions necessary to download and export SecurityHub findings,
    whether invoked as a Lambda or from the command line.
    """
    # Get the SSM parameters and a client for further SSM operations
    ssmActor = csvo.SsmActor(role=role, region=region)

    # Get a list of Security Hub regions we wish to act on
    regions = choose(
        os.environ.get("CSV_SECURITYHUB_REGIONLIST"),
        re.compile(r"\s*,\s*").split(getattr(ssmActor, "/csvManager/regionList", region)),
        ssmActor.getSupportedRegions(service="securityhub")
    )
    
    _LOGGER.info("493040i selected SecurityHub regions %s" % regions)

    # Get information about the bucket
    folder = getattr(ssmActor, "/csvManager/folder/findings", None)
    bucket = bucket if bucket else getattr(ssmActor, "/csvManager/bucket", None)

    _LOGGER.debug(f'493050d writing to s3://{bucket}/{folder}/*') 

    # A client to act on the bucket
    s3Actor = csvo.S3Actor(
        bucket=bucket, 
        folder=folder, 
        region=region, 
        role=role
    )

    # Filename where file can be stored locally
    localFile = s3Actor.filePath()

    # Now obtain a client for SecurityHub regions
    hubActor = csvo.HubActor(
        role=role,
        region=regions
    )

    # Obtain the findings for all applicable regions
    hubActor.downloadFindings(filters=filters,limit=limit)

    if hubActor.count <= 0:
        _LOGGER.warning("493060w no findings downloaded")
    else:
        _LOGGER.info(f'493070i preparing to write {hubActor.count} findings')

        first = True

        with open(localFile, 'w') as target:
            for finding in hubActor.getFinding():
                findingObject = csvo.Finding(finding, actor=hubActor)

                # Start the CSV file with a header
                if first:
                    _LOGGER.debug("493080d finding object %s keys %s" \
                        % (findingObject, findingObject.columns))

                    writer = csv.DictWriter(target, 
                        fieldnames=findingObject.columns)

                    writer.writeheader()

                # Write the finding
                writer.writerow(findingObject.rowMap)

                first = False

        # Announce completion of write
        _LOGGER.info("493090i findings written to %s" % localFile)

        # Place the object in the S3 bucket
        s3Actor.put()

        _LOGGER.info('493100i uploaded to ' + 
            f's3://{s3Actor.bucket}/{s3Actor.objectKey}')

        # Determine whether to retain the local file or not
        if retain:
            _LOGGER.warning("493110w local file %s retained" % localFile)
        else:
            os.unlink(localFile)

            _LOGGER.info("493120i local file deleted")

        # Return details to caller
        answer = {
            "success" : True ,
            "message" : "Export succeeded" ,
            "bucket" : s3Actor.bucket ,
            "exportKey" : s3Actor.objectKey
        }

    return answer

################################################################################
#### Step Functions callback methods with enhanced error handling
################################################################################
def send_task_success(task_token, result):
    """
    Send a success callback to Step Functions with the task token and result.
    Includes retry logic and comprehensive error handling.
    """
    if not task_token:
        _LOGGER.error("493181e Cannot send task success: task token is empty")
        raise ValueError("Task token is required for Step Functions callback")
    
    max_retries = 3
    retry_delay = 1  # Start with 1 second
    
    for attempt in range(max_retries):
        try:
            stepfunctions_client = boto3.client('stepfunctions')
            
            # Validate result can be serialized to JSON
            try:
                json_output = json.dumps(result)
            except (TypeError, ValueError) as json_error:
                _LOGGER.error(f"493182e Result cannot be serialized to JSON: {json_error}")
                raise ValueError(f"Invalid result format for Step Functions: {json_error}")
            
            stepfunctions_client.send_task_success(
                taskToken=task_token,
                output=json_output
            )
            _LOGGER.info("493180i Task success callback sent to Step Functions")
            return  # Success, exit retry loop
            
        except stepfunctions_client.exceptions.InvalidToken as e:
            _LOGGER.error(f"493183e Invalid task token: {e}")
            # Don't retry for invalid token
            raise
        except stepfunctions_client.exceptions.TaskTimedOut as e:
            _LOGGER.error(f"493184e Task has timed out: {e}")
            # Don't retry for timed out task
            raise
        except stepfunctions_client.exceptions.TaskDoesNotExist as e:
            _LOGGER.error(f"493185e Task does not exist: {e}")
            # Don't retry for non-existent task
            raise
        except Exception as e:
            _LOGGER.warning(f"493186w Attempt {attempt + 1}/{max_retries} failed to send task success: {e}")
            if attempt == max_retries - 1:
                _LOGGER.error(f"493190e Failed to send task success callback after {max_retries} attempts: {e}")
                raise
            else:
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff

def send_task_failure(task_token, error_message, error_cause=None):
    """
    Send a failure callback to Step Functions with the task token and error details.
    Includes retry logic and comprehensive error handling.
    """
    if not task_token:
        _LOGGER.error("493201e Cannot send task failure: task token is empty")
        raise ValueError("Task token is required for Step Functions callback")
    
    max_retries = 3
    retry_delay = 1  # Start with 1 second
    
    for attempt in range(max_retries):
        try:
            stepfunctions_client = boto3.client('stepfunctions')
            
            # Ensure error message is a string and not too long
            error_msg = str(error_message)[:256]  # Limit error message length
            error_cause_str = str(error_cause or error_message)[:32768]  # Step Functions limit
            
            stepfunctions_client.send_task_failure(
                taskToken=task_token,
                error=error_msg,
                cause=error_cause_str
            )
            _LOGGER.info("493200i Task failure callback sent to Step Functions")
            return  # Success, exit retry loop
            
        except stepfunctions_client.exceptions.InvalidToken as e:
            _LOGGER.error(f"493203e Invalid task token: {e}")
            # Don't retry for invalid token
            raise
        except stepfunctions_client.exceptions.TaskTimedOut as e:
            _LOGGER.error(f"493204e Task has timed out: {e}")
            # Don't retry for timed out task
            raise
        except stepfunctions_client.exceptions.TaskDoesNotExist as e:
            _LOGGER.error(f"493205e Task does not exist: {e}")
            # Don't retry for non-existent task
            raise
        except Exception as e:
            _LOGGER.warning(f"493206w Attempt {attempt + 1}/{max_retries} failed to send task failure: {e}")
            if attempt == max_retries - 1:
                _LOGGER.error(f"493210e Failed to send task failure callback after {max_retries} attempts: {e}")
                raise
            else:
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff

################################################################################
#### Pagination State Management
################################################################################
class PaginationState:
    """
    Represents the pagination state for Step Function execution.
    """
    def __init__(self, next_token="", execution_id="", processed_count=0):
        self.next_token = next_token
        self.execution_id = execution_id
        self.processed_count = processed_count
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self):
        """Convert state to dictionary for JSON serialization."""
        return {
            "nextToken": self.next_token,
            "executionId": self.execution_id,
            "processedCount": self.processed_count,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data):
        """Create PaginationState from dictionary."""
        if not data:
            return cls()
        
        state = cls(
            next_token=data.get("nextToken", ""),
            execution_id=data.get("executionId", ""),
            processed_count=data.get("processedCount", 0)
        )
        state.timestamp = data.get("timestamp", datetime.utcnow().isoformat())
        return state

def save_pagination_state(state, role=None, region=None):
    """
    Save pagination state to SSM parameters.
    
    Args:
        state (PaginationState): The pagination state to save
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
    """
    try:
        ssmActor = csvo.SsmActor(role=role, region=region)
        
        # Save individual state components
        ssmActor.putValue(
            name="/csvManager/export/nextToken",
            description="Pagination token for Security Hub findings export",
            value=state.next_token or "",
            type="String"
        )
        
        ssmActor.putValue(
            name="/csvManager/export/currentExecution",
            description="Current Step Function execution ID",
            value=state.execution_id or "",
            type="String"
        )
        
        ssmActor.putValue(
            name="/csvManager/export/processedCount",
            description="Number of findings processed in current execution",
            value=str(state.processed_count),
            type="String"
        )
        
        ssmActor.putValue(
            name="/csvManager/export/timestamp",
            description="Timestamp of last state update",
            value=state.timestamp,
            type="String"
        )
        
        _LOGGER.info(f"493220i Pagination state saved for execution {state.execution_id}")
        
    except Exception as e:
        _LOGGER.error(f"493230e Failed to save pagination state: {e}")
        raise

def load_pagination_state(role=None, region=None):
    """
    Load pagination state from SSM parameters.
    
    Args:
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
        
    Returns:
        PaginationState: The loaded pagination state
    """
    try:
        ssmActor = csvo.SsmActor(role=role, region=region)
        
        # Load state parameters
        parameters = [
            "/csvManager/export/nextToken",
            "/csvManager/export/currentExecution", 
            "/csvManager/export/processedCount",
            "/csvManager/export/timestamp"
        ]
        
        values = ssmActor.getValue(parameters)
        
        state_data = {
            "nextToken": values.get("/csvManager/export/nextToken", ""),
            "executionId": values.get("/csvManager/export/currentExecution", ""),
            "processedCount": int(values.get("/csvManager/export/processedCount", "0") or "0"),
            "timestamp": values.get("/csvManager/export/timestamp", "")
        }
        
        state = PaginationState.from_dict(state_data)
        _LOGGER.info(f"493240i Pagination state loaded for execution {state.execution_id}")
        return state
        
    except Exception as e:
        _LOGGER.error(f"493250e Failed to load pagination state: {e}")
        # Return empty state on error
        return PaginationState()

def validate_pagination_state(state, expected_execution_id):
    """
    Validate pagination state for consistency and corruption detection.
    
    Args:
        state (PaginationState): The pagination state to validate
        expected_execution_id (str): Expected execution ID
        
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        # Check if state exists
        if not state:
            return False, "No pagination state found"
        
        # Check execution ID consistency
        if expected_execution_id and state.execution_id != expected_execution_id:
            return False, f"Execution ID mismatch: expected {expected_execution_id}, got {state.execution_id}"
        
        # Check for reasonable processed count
        if state.processed_count < 0:
            return False, f"Invalid processed count: {state.processed_count}"
        
        # Check timestamp validity
        if state.timestamp:
            try:
                datetime.fromisoformat(state.timestamp.replace('Z', '+00:00'))
            except ValueError:
                return False, f"Invalid timestamp format: {state.timestamp}"
        
        # Check for stale state (older than 24 hours)
        if state.timestamp:
            try:
                state_time = datetime.fromisoformat(state.timestamp.replace('Z', '+00:00'))
                age_hours = (datetime.utcnow() - state_time.replace(tzinfo=None)).total_seconds() / 3600
                if age_hours > 24:
                    return False, f"State is too old: {age_hours:.1f} hours"
            except Exception:
                # If we can't parse timestamp, consider it invalid but not critical
                pass
        
        _LOGGER.info(f"493260i Pagination state validation passed for execution {state.execution_id}")
        return True, "State is valid"
        
    except Exception as e:
        _LOGGER.error(f"493270e State validation failed: {e}")
        return False, f"Validation error: {e}"

def cleanup_pagination_state(role=None, region=None):
    """
    Clean up pagination state parameters after successful completion.
    
    Args:
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
    """
    try:
        ssmActor = csvo.SsmActor(role=role, region=region)
        
        # Clear all pagination state parameters
        parameters_to_clear = [
            "/csvManager/export/nextToken",
            "/csvManager/export/currentExecution",
            "/csvManager/export/processedCount",
            "/csvManager/export/timestamp"
        ]
        
        for param in parameters_to_clear:
            ssmActor.putValue(
                name=param,
                description=f"Cleared pagination state parameter",
                value="",
                type="String"
            )
        
        _LOGGER.info("493290i Pagination state cleaned up successfully")
        
    except Exception as e:
        _LOGGER.error(f"493300e Failed to cleanup pagination state: {e}")
        raise

def reset_corrupted_state(role=None, region=None, execution_id=None):
    """
    Reset pagination state when corruption is detected.
    
    Args:
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
        execution_id (str): Current execution ID to set in reset state
    """
    try:
        _LOGGER.warning("493310w Resetting corrupted pagination state")
        
        # Create fresh state
        fresh_state = PaginationState(
            next_token="",
            execution_id=execution_id or str(uuid.uuid4()),
            processed_count=0
        )
        
        # Save the fresh state
        save_pagination_state(fresh_state, role=role, region=region)
        
        _LOGGER.info(f"493320i Pagination state reset for execution {fresh_state.execution_id}")
        return fresh_state
        
    except Exception as e:
        _LOGGER.error(f"493330e Failed to reset corrupted state: {e}")
        raise
        
        state = PaginationState.from_dict(state_data)
        _LOGGER.info(f"493240i Pagination state loaded for execution {state.execution_id}")
        
        return state
        
    except Exception as e:
        _LOGGER.error(f"493250e Failed to load pagination state: {e}")
        # Return empty state on error
        return PaginationState()

def validate_pagination_state(state, current_execution_id):
    """
    Validate pagination state and detect corruption.
    
    Args:
        state (PaginationState): The pagination state to validate
        current_execution_id (str): Current Step Function execution ID
        
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        # Check if state belongs to current execution
        if state.execution_id and state.execution_id != current_execution_id:
            return False, f"State execution ID mismatch: {state.execution_id} != {current_execution_id}"
        
        # Check if processed count is valid
        if state.processed_count < 0:
            return False, f"Invalid processed count: {state.processed_count}"
        
        # Check timestamp validity (state shouldn't be too old - 24 hours)
        try:
            state_time = datetime.fromisoformat(state.timestamp.replace('Z', '+00:00'))
            current_time = datetime.utcnow()
            time_diff = current_time - state_time.replace(tzinfo=None)
            
            if time_diff.total_seconds() > 86400:  # 24 hours
                return False, f"State is too old: {state.timestamp}"
                
        except Exception as time_error:
            _LOGGER.warning(f"493260w Could not validate timestamp: {time_error}")
        
        _LOGGER.info(f"493270i Pagination state validation passed for execution {current_execution_id}")
        return True, "State is valid"
        
    except Exception as e:
        _LOGGER.error(f"493280e Error validating pagination state: {e}")
        return False, f"Validation error: {str(e)}"

def cleanup_pagination_state(role=None, region=None):
    """
    Clean up pagination state for completed or failed executions.
    
    Args:
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
    """
    try:
        ssmActor = csvo.SsmActor(role=role, region=region)
        
        # Clear all pagination state parameters
        parameters_to_clear = [
            "/csvManager/export/nextToken",
            "/csvManager/export/currentExecution",
            "/csvManager/export/processedCount",
            "/csvManager/export/timestamp"
        ]
        
        for param in parameters_to_clear:
            ssmActor.putValue(
                name=param,
                description=f"Cleared pagination state parameter",
                value="",
                type="String"
            )
        
        _LOGGER.info("493290i Pagination state cleaned up successfully")
        
    except Exception as e:
        _LOGGER.error(f"493300e Failed to cleanup pagination state: {e}")
        raise

def reset_corrupted_state(role=None, region=None, execution_id=None):
    """
    Reset pagination state when corruption is detected.
    
    Args:
        role (str): IAM role ARN for SSM operations
        region (str): AWS region for SSM operations
        execution_id (str): Current execution ID to set in reset state
    """
    try:
        _LOGGER.warning("493310w Resetting corrupted pagination state")
        
        # Create fresh state
        fresh_state = PaginationState(
            next_token="",
            execution_id=execution_id or str(uuid.uuid4()),
            processed_count=0
        )
        
        # Save the fresh state
        save_pagination_state(fresh_state, role=role, region=region)
        
        _LOGGER.info(f"493320i Pagination state reset for execution {fresh_state.execution_id}")
        return fresh_state
        
    except Exception as e:
        _LOGGER.error(f"493330e Failed to reset corrupted state: {e}")
        raise

################################################################################
#### Enhanced error recovery mechanisms
################################################################################
def handle_interrupted_execution(execution_id, role=None, region=None):
    """
    Handle recovery from interrupted Step Function executions.
    
    Args:
        execution_id (str): The execution ID to recover
        role (str): IAM role ARN for operations
        region (str): AWS region for operations
        
    Returns:
        dict: Recovery information and next steps
    """
    try:
        _LOGGER.info(f"493370i Attempting recovery for interrupted execution {execution_id}")
        
        # Load current state
        current_state = load_pagination_state(role=role, region=region)
        
        # Validate state for this execution
        is_valid, validation_error = validate_pagination_state(current_state, execution_id)
        
        if not is_valid:
            _LOGGER.warning(f"493371w State validation failed during recovery: {validation_error}")
            # Reset state and start fresh
            fresh_state = reset_corrupted_state(role=role, region=region, execution_id=execution_id)
            return {
                "recovery_action": "reset_state",
                "message": f"State was corrupted, reset to fresh state: {validation_error}",
                "next_token": None,
                "processed_count": 0
            }
        
        # State is valid, can resume from where we left off
        _LOGGER.info(f"493372i Valid state found, can resume from token: {current_state.next_token[:20] if current_state.next_token else 'None'}...")
        
        return {
            "recovery_action": "resume",
            "message": f"Can resume from previous state",
            "next_token": current_state.next_token,
            "processed_count": current_state.processed_count
        }
        
    except Exception as recovery_error:
        _LOGGER.error(f"493373e Recovery failed: {recovery_error}")
        
        # Last resort: reset everything
        try:
            fresh_state = reset_corrupted_state(role=role, region=region, execution_id=execution_id)
            return {
                "recovery_action": "emergency_reset",
                "message": f"Recovery failed, performed emergency reset: {recovery_error}",
                "next_token": None,
                "processed_count": 0
            }
        except Exception as reset_error:
            _LOGGER.error(f"493374e Emergency reset failed: {reset_error}")
            raise RuntimeError(f"Complete recovery failure: {reset_error}") from reset_error

def publish_cloudwatch_metrics(execution_context, result=None, error=None, region=None):
    """
    Publish custom CloudWatch metrics for Step Function monitoring.
    
    Args:
        execution_context (dict): Context information about the execution
        result (dict): Successful execution result (optional)
        error (Exception): Error information (optional)
        region (str): AWS region for CloudWatch operations
    """
    try:
        cloudwatch_client = boto3.client('cloudwatch', region_name=region)
        
        # Base dimensions for all metrics
        base_dimensions = [
            {
                'Name': 'StateMachine',
                'Value': execution_context.get('state_machine_name', 'SecurityHubExport')
            },
            {
                'Name': 'Function',
                'Value': execution_context.get('function_name', 'sh_csv_exporter')
            }
        ]
        
        # Prepare metrics data
        metric_data = []
        timestamp = datetime.utcnow()
        
        if result:
            # Pagination progress metric (percentage of completion)
            processed_count = result.get("processedCount", 0)
            current_batch = result.get("currentBatch", 0)
            has_more = result.get("hasMore", False)
            
            # Calculate progress percentage (estimated)
            if not has_more:
                progress_percentage = 100.0
            else:
                # Estimate progress based on batch number (rough approximation)
                progress_percentage = min(95.0, current_batch * 10.0)  # Cap at 95% until complete
            
            metric_data.append({
                'MetricName': 'PaginationProgress',
                'Dimensions': base_dimensions,
                'Value': progress_percentage,
                'Unit': 'Percent',
                'Timestamp': timestamp
            })
            
            # Processing rate metric (findings per minute)
            batch_size = result.get("lastBatchSize", 0)
            if batch_size > 0:
                # Estimate processing rate based on batch size
                # This is a rough estimate - in production you'd track actual time
                estimated_processing_rate = batch_size / 5.0  # Assume 5 minutes per batch
                
                metric_data.append({
                    'MetricName': 'FindingsProcessedPerMinute',
                    'Dimensions': base_dimensions,
                    'Value': estimated_processing_rate,
                    'Unit': 'Count/Second',
                    'Timestamp': timestamp
                })
            
            # Batch size metric
            if batch_size > 0:
                metric_data.append({
                    'MetricName': 'BatchSize',
                    'Dimensions': base_dimensions,
                    'Value': batch_size,
                    'Unit': 'Count',
                    'Timestamp': timestamp
                })
            
            # Total processed count metric
            metric_data.append({
                'MetricName': 'TotalProcessedFindings',
                'Dimensions': base_dimensions,
                'Value': processed_count,
                'Unit': 'Count',
                'Timestamp': timestamp
            })
            
            # Execution success metric
            metric_data.append({
                'MetricName': 'ExecutionSuccess',
                'Dimensions': base_dimensions,
                'Value': 1,
                'Unit': 'Count',
                'Timestamp': timestamp
            })
            
        if error:
            # Error count metric
            metric_data.append({
                'MetricName': 'ExecutionErrors',
                'Dimensions': base_dimensions + [
                    {
                        'Name': 'ErrorType',
                        'Value': type(error).__name__
                    }
                ],
                'Value': 1,
                'Unit': 'Count',
                'Timestamp': timestamp
            })
        
        # Execution duration metric (if available from context)
        if execution_context.get('execution_duration'):
            metric_data.append({
                'MetricName': 'ExecutionDuration',
                'Dimensions': base_dimensions,
                'Value': execution_context['execution_duration'],
                'Unit': 'Seconds',
                'Timestamp': timestamp
            })
        
        # Memory usage metric (if available from context)
        if execution_context.get('memory_used'):
            metric_data.append({
                'MetricName': 'MemoryUtilization',
                'Dimensions': base_dimensions,
                'Value': execution_context['memory_used'],
                'Unit': 'Percent',
                'Timestamp': timestamp
            })
        
        # Publish metrics in batches (CloudWatch limit is 20 metrics per call)
        batch_size = 20
        for i in range(0, len(metric_data), batch_size):
            batch = metric_data[i:i + batch_size]
            
            cloudwatch_client.put_metric_data(
                Namespace='SecurityHub/CSVExport',
                MetricData=batch
            )
        
        _LOGGER.info(f"493390i Published {len(metric_data)} CloudWatch metrics")
        
    except Exception as metrics_error:
        _LOGGER.warning(f"493391w Failed to publish CloudWatch metrics: {metrics_error}")

def log_step_function_metrics(execution_context, result=None, error=None):
    """
    Log comprehensive metrics for Step Function monitoring and debugging.
    
    Args:
        execution_context (dict): Context information about the execution
        result (dict): Successful execution result (optional)
        error (Exception): Error information (optional)
    """
    try:
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": execution_context.get("execution_id"),
            "invocation_id": execution_context.get("invocation_id"),
            "function": execution_context.get("function", "unknown"),
            "stage": execution_context.get("stage", "unknown"),
            "has_task_token": execution_context.get("has_task_token", False),
            "batch_size": execution_context.get("batch_size"),
            "region": execution_context.get("region")
        }
        
        if result:
            metrics.update({
                "status": "success",
                "processed_count": result.get("processedCount", 0),
                "current_batch": result.get("currentBatch", 0),
                "has_more": result.get("hasMore", False),
                "export_key": result.get("exportKey")
            })
        
        if error:
            metrics.update({
                "status": "error",
                "error_type": type(error).__name__,
                "error_message": str(error)[:500]  # Limit message length
            })
        
        # Log as structured JSON for monitoring systems
        _LOGGER.info(f"493380i STEP_FUNCTION_METRICS: {json.dumps(metrics)}")
        
        # Also publish to CloudWatch metrics
        publish_cloudwatch_metrics(execution_context, result, error, execution_context.get("region"))
        
    except Exception as log_error:
        _LOGGER.warning(f"493381w Failed to log metrics: {log_error}")

################################################################################
#### Lambda handler with comprehensive error handling and recovery
################################################################################
def lambdaHandler ( event = None, context = None ):
    """
    Perform the operations necessary if CsvExporter is invoked as a Lambda
    function with comprehensive error handling and recovery mechanisms.
    """
    # Track execution start time for duration metrics
    execution_start_time = time.time()
    
    # Initialize execution context for error tracking and monitoring
    execution_context = {
        "function": "lambdaHandler",
        "invocation_id": context.aws_request_id if context else str(uuid.uuid4()),
        "remaining_time": context.get_remaining_time_in_millis() if context else None,
        "memory_limit": context.memory_limit_in_mb if context else None,
        "function_name": context.function_name if context else "sh_csv_exporter",
        "state_machine_name": "SecurityHubExport",
        "execution_start_time": execution_start_time
    }
    
    task_token = None  # Initialize for error handling
    
    try:
        # Extract and validate event parameters
        try:
            role = event.get("role") if event else None
            region = event.get("region") if event else None
            
            if event and 'filters' in event.keys():
                filters = getFilters(event.get("filters", {}))
            else:
                filters = event if event else {}
                
            bucket = event.get("bucket") if event else None
            retain = event.get("retainLocal", False) if event else False
            limit = event.get("limit", 0) if event else 0
            eventData = event.get("event") if event else None
            
            # Extract task token and pagination parameters for Step Functions support
            task_token = event.get("taskToken") if event else None
            next_token = event.get("nextToken") if event else None
            batch_size = event.get("batchSize", 1000) if event else 1000
            execution_id = event.get("executionId") if event else None
            
            execution_context.update({
                "has_task_token": bool(task_token),
                "has_next_token": bool(next_token),
                "batch_size": batch_size,
                "execution_id": execution_id,
                "role": role
            })
            
        except Exception as param_error:
            _LOGGER.error(f"493359e Parameter extraction failed: {param_error}")
            raise ValueError(f"Invalid event parameters: {param_error}") from param_error

        # If no region is specified it must be obtained from the environment
        if not region:
            region = os.environ.get("CSV_PRIMARY_REGION")
            if region:
                _LOGGER.info(f"493130i obtained region {region} from environment")
            else:
                raise ValueError("No region specified in event or environment")

        execution_context["region"] = region

        # This is where we will store the result
        answer = {}

        # Determine if Lambda was invoked manually or via an event
        if eventData:
            # Handle both dictionary and string event data
            if isinstance(eventData, dict):
                eventType = eventData.get("detail-type", "UNKNOWN")
            elif isinstance(eventData, str):
                eventType = eventData  # Use the string value directly
            else:
                eventType = str(eventData)  # Convert to string as fallback
            _LOGGER.info("493140i Lambda invoked by %s" % eventType)
            execution_context["invocation_type"] = eventType
        else:
            _LOGGER.info("493150i Lambda invoked extemporaneously")
            execution_context["invocation_type"] = "manual"

        # Check remaining execution time for Step Function scenarios
        if context and task_token:
            remaining_time = context.get_remaining_time_in_millis()
            if remaining_time < 30000:  # Less than 30 seconds remaining
                _LOGGER.warning(f"493360w Low remaining execution time: {remaining_time}ms")
                # Could implement early termination logic here

        # Perform the real work with comprehensive error handling
        try:
            # Use pagination-aware executor if task token is present
            if task_token:
                _LOGGER.info("493141i Using pagination-aware executor for Step Function integration")
                
                # Check for interrupted execution recovery
                if execution_id and not next_token:
                    recovery_info = handle_interrupted_execution(execution_id, role=role, region=region)
                    _LOGGER.info(f"493382i Recovery info: {recovery_info}")
                    
                    if recovery_info["recovery_action"] == "resume":
                        next_token = recovery_info["next_token"]
                        _LOGGER.info(f"493383i Resuming from recovered state with token: {next_token[:20] if next_token else 'None'}...")
                
                # Add execution context to the executor call
                result = executor_with_pagination(
                    role=role,
                    region=region,
                    filters=filters,
                    bucket=bucket,
                    retain=retain,
                    limit=limit,
                    next_token=next_token,
                    task_token=task_token,
                    batch_size=batch_size,
                    execution_id=execution_id
                )

                answer = {
                    "message": result.get("message"),
                    "bucket": result.get("bucket"),
                    "exportKey": result.get("exportKey"),
                    "hasMore": result.get("hasMore", False),
                    "nextToken": result.get("nextToken"),
                    "processedCount": result.get("processedCount", 0),
                    "currentBatch": result.get("currentBatch", 0),
                    "lastBatchSize": result.get("lastBatchSize", 0),
                    "resultCode": 200 if result.get("success") else 400,
                    "executionContext": execution_context
                }

                # Calculate execution duration and memory usage for metrics
                execution_duration = time.time() - execution_start_time
                execution_context["execution_duration"] = execution_duration
                
                # Estimate memory usage if context is available
                if context:
                    remaining_time = context.get_remaining_time_in_millis()
                    initial_time = 900000  # 15 minutes default timeout
                    time_used = initial_time - remaining_time
                    # Rough memory usage estimation (this is approximate)
                    execution_context["memory_used"] = min(100, (time_used / initial_time) * 100)

                # Log metrics for monitoring
                log_step_function_metrics(execution_context, result=answer)

                # Send success callback to Step Functions with retry logic
                try:
                    send_task_success(task_token, answer)
                    _LOGGER.info("493361i Successfully sent task success callback")
                    return  # Don't return the answer when using task token
                    
                except Exception as callback_error:
                    _LOGGER.error(f"493362e Failed to send success callback: {callback_error}")
                    # Log the error but don't re-raise since the work was completed
                    return
                    
            else:
                # Use original executor for backward compatibility
                _LOGGER.info("493142i Using original executor for direct invocation")
                result = executor(
                    role=role,
                    region=region,
                    filters=filters,
                    bucket=bucket,
                    retain=retain,
                    limit=limit
                )

                answer = {
                    "message": result.get("message"),
                    "bucket": result.get("bucket"),
                    "exportKey": result.get("exportKey"),
                    "resultCode": 200 if result.get("success") else 400,
                    "executionContext": execution_context
                }

        except Exception as execution_error:
            execution_context["execution_error"] = str(execution_error)
            _LOGGER.error(f"493363e Execution failed: {execution_error}")
            raise

    # Catch any errors with comprehensive error handling and recovery
    except Exception as thrown:
        errorType = type(thrown).__name__
        errorMessage = str(thrown)
        errorTrace = traceback.format_tb(thrown.__traceback__, limit=5)

        # Log comprehensive error information
        _LOGGER.error("493160e Lambda failed (%s): %s\n%s" \
            % (errorType, errorMessage, errorTrace))
        
        # Log execution context for debugging
        _LOGGER.error(f"493364e Execution context: {json.dumps(execution_context, indent=2)}")
        
        # Calculate execution duration for error metrics
        execution_duration = time.time() - execution_start_time
        execution_context["execution_duration"] = execution_duration
        
        # Log metrics for monitoring
        log_step_function_metrics(execution_context, error=thrown)
        
        # Prepare error response
        answer = { 
            "message": errorMessage,
            "errorType": errorType,
            "traceback": errorTrace,
            "bucket": None,
            "exportKey": None,
            "resultCode": 500,
            "executionContext": execution_context
        }

        # If task token is present, send failure callback to Step Functions
        if task_token:
            try:
                error_cause = json.dumps({
                    "errorType": errorType,
                    "errorMessage": errorMessage,
                    "traceback": errorTrace,
                    "executionContext": execution_context
                })
                
                # Attempt to reset corrupted state on critical errors
                if execution_context.get("execution_id") and "state" in errorMessage.lower():
                    try:
                        _LOGGER.info("493365i Attempting to reset corrupted state due to state-related error")
                        reset_corrupted_state(
                            role=execution_context.get("role"),
                            region=execution_context.get("region"),
                            execution_id=execution_context.get("execution_id")
                        )
                    except Exception as reset_error:
                        _LOGGER.warning(f"493366w Failed to reset state on error: {reset_error}")
                
                send_task_failure(task_token, errorType, error_cause)
                _LOGGER.info("493367i Successfully sent task failure callback")
                
            except Exception as callback_error:
                _LOGGER.error(f"493368e Failed to send failure callback: {callback_error}")
                # Continue to return error response even if callback fails
            
            return  # Don't return the answer when using task token

    return answer

################################################################################
#### Main body is invoked if this is a command invocation
################################################################################
if __name__ == "__main__":
    """
    Need to make regions etc. configurable
    """
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--role-arn", required=False, dest="roleArn",
            help="The assumable role ARN to access SecurityHub")
        parser.add_argument("--filters", default='{}', required=False, 
            help="Filters to apply to findings")
        parser.add_argument("--bucket", required=False, 
            help="S3 bucket to store findings")
        parser.add_argument("--limit", required=False, type=int, default=0,
            help="Limit number of findings retrieved")
        parser.add_argument("--retain-local", action="store_true", 
            dest="retainLocal", default=False, help="Retain local file")
        parser.add_argument("--primary-region", dest="region", required=True,
            help="Primary region for operations")

        arguments = parser.parse_args()

        executor(
            role=arguments.roleArn, 
            filters=getFilters(arguments.filters),
            bucket=arguments.bucket, 
            limit=arguments.limit, 
            retain=arguments.retainLocal,
            region=arguments.region
        )

    except Exception as thrown:
        _LOGGER.exception("493170t unexpected command invocation error %s" \
            % str(thrown))
