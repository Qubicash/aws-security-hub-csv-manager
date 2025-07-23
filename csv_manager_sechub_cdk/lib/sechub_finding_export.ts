import { Stack, StackProps, Duration, CfnParameter, Fn, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as stepfunctionstasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Construct } from 'constructs';
import { join } from 'path';
import { principalsJson } from '../config.json';

export class SecHubExportStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Stack Parameters
    const Frequency = new CfnParameter(this, 'Frequency', {
      type: 'String',
      description: 'A cron or rate expression for how often the export occurs.',
      default: 'cron(0 8 ? * SUN *)'
    });

    const Partition = new CfnParameter(this, 'Partition', {
      type: 'String',
      description: 'The partition in which CSV Manager for Security Hub will operate.',
      default: 'aws'
    });

    const Regions = new CfnParameter(this, 'Regions', {
      type: 'String',
      description: 'The comma-delimeted list of regions in which CSV Manager for Security Hub will operate.',
      default: this.region
    });

    const PrimaryRegion = new CfnParameter(this, 'PrimaryRegion', {
      type: 'String',
      description: 'The region in which the S3 bucket and SSM parameters are stored.',
      default: this.region
    });

    const FindingsFolder = new CfnParameter(this, 'FindingsFolder', {
      type: 'String',
      description: 'Folder that will contain Lambda code & CloudFormation templates.',
      default: 'Findings'
    });

    const CodeFolder = new CfnParameter(this, 'CodeFolder', {
      type: 'String',
      description: 'Folder that will contain Lambda code & CloudFormation templates.',
      default: 'Code'
    });

    const ExpirationPeriod = new CfnParameter(this, 'ExpirationPeriod', {
      type: 'Number',
      description: 'Maximum days to retain exported findings.',
      default: 365
    });

    const GlacierTransitionPeriod = new CfnParameter(this, 'GlacierTransitionPeriod', {
      type: 'Number',
      description: 'Maximum days before exported findings are moved to AWS Glacier.',
      default: 31
    });

    // KMS Key for S3 Bucket for Security Hub Export
    const s3_kms_key = new kms.Key(this, 's3_kms_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key for security hub findings in S3.',
      enableKeyRotation: false,
      alias: 'sh_export_key'
    });

    // S3 Bucket for Security Hub Export
    const security_hub_export_bucket = new s3.Bucket(this, 'security_hub_export_bucket', {
      removalPolicy: RemovalPolicy.RETAIN,
      bucketKeyEnabled: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: s3_kms_key,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      publicReadAccess: false,
      lifecycleRules: [{
        expiration: Duration.days(ExpirationPeriod.valueAsNumber),
        transitions: [{
            storageClass: s3.StorageClass.GLACIER,
            transitionAfter: Duration.days(GlacierTransitionPeriod.valueAsNumber)
        }]
    }]
    });

    // Be sure to add valid IAM principals to the principalsJson object in ../config.json object.
    principalsJson.principals.forEach((principal: string) => {
      security_hub_export_bucket.addToResourcePolicy(new iam.PolicyStatement({
        actions: [
          's3:GetObject*',
          's3:ListBucket',
          's3:PutObject*'
        ],
        resources: [
          security_hub_export_bucket.bucketArn,
          security_hub_export_bucket.arnForObjects('*')
        ],
        principals: [
          new iam.ArnPrincipal(principal)],
      }));
  })

    // Step Function IAM role for orchestrating the CSV export process
    const stepFunctionRole = new iam.Role(this, 'stepFunctionRole', {
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com'),
      roleName: 'SecurityHub_StepFunction_Role',
      description: 'IAM role for Step Function to orchestrate Security Hub CSV export process'
    });

    // Lambda Function for CSV exporter 
    const secub_csv_manager_role = new iam.Role(this, 'secub_csv_manager_role', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal("lambda.amazonaws.com"),
        new iam.ServicePrincipal("ec2.amazonaws.com"),
        new iam.ServicePrincipal("ssm.amazonaws.com")
    ),
      roleName: "SecurityHub_CSV_Exporter",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaExporterSHLogExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    security_hub_export_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetObject*',
        's3:ListBucket',
        's3:PutObject*'
      ],
      resources: [
        security_hub_export_bucket.bucketArn,
        security_hub_export_bucket.arnForObjects('*')
      ],
      principals: [
        new iam.ArnPrincipal(secub_csv_manager_role.roleArn)],
    }));

    const sh_csv_exporter_function = new lambda.Function(this, 'secub_csv_exporter_function', {
      runtime: lambda.Runtime.PYTHON_3_9,
      functionName: this.stackName + '_' + this.account + '_sh_csv_exporter',
      code: lambda.Code.fromAsset(join(__dirname, "../lambdas")),
      handler: 'csvExporter.lambdaHandler',
      description: 'Export SecurityHub findings to CSV in S3 bucket.',
      timeout: Duration.seconds(900),
      memorySize: 512,
      role: secub_csv_manager_role,
      reservedConcurrentExecutions: 100,
      environment:{
        CSV_PRIMARY_REGION: PrimaryRegion.valueAsString
      },
    });

    const sh_csv_updater_function = new lambda.Function(this, 'secub_csv_updater_function', {
      runtime: lambda.Runtime.PYTHON_3_9,
      functionName: this.stackName + '_' + this.account + '_sh_csv_updater',
      code: lambda.Code.fromAsset(join(__dirname, "../lambdas")),
      handler: 'csvUpdater.lambdaHandler',
      description: 'Update SecurityHub findings to CSV in S3 bucket.',
      timeout: Duration.seconds(900),
      memorySize: 512,
      role: secub_csv_manager_role,
      reservedConcurrentExecutions: 100,
      environment:{
        CSV_PRIMARY_REGION: PrimaryRegion.valueAsString
      },
    });

    // Policy document for Step Function permissions (created after Lambda functions)
    const stepFunctionPolicyDoc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "LambdaInvokeAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "lambda:InvokeFunction"
          ],
          resources: [
            sh_csv_exporter_function.functionArn
          ]
        }),
        new iam.PolicyStatement({
          sid: "TaskTokenAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "states:SendTaskSuccess",
            "states:SendTaskFailure"
          ],
          resources: [
            "*"
          ]
        }),
        new iam.PolicyStatement({
          sid: "CloudWatchLogsAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ],
          resources: [
            Fn.join('', ["arn:", this.partition, ":logs:", this.region, ":", this.account, ":log-group:/aws/stepfunctions/*"]),
            Fn.join('', ["arn:", this.partition, ":logs:", this.region, ":", this.account, ":log-group:/aws/lambda/*"])
          ]
        }),
        new iam.PolicyStatement({
          sid: "CloudWatchMetricsAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "cloudwatch:PutMetricData",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics"
          ],
          resources: ["*"],
          conditions: {
            StringEquals: {
              "cloudwatch:namespace": [
                "SecurityHub/CSVExport",
                "AWS/StepFunctions",
                "AWS/Lambda"
              ]
            }
          }
        })
      ]
    });

    // Create managed policy for Step Function role
    new iam.ManagedPolicy(this, 'stepFunctionManagedPolicy', {
      description: 'Managed policy for Step Function to orchestrate Security Hub CSV export',
      document: stepFunctionPolicyDoc,
      managedPolicyName: 'SecurityHub_StepFunction_Policy',
      roles: [stepFunctionRole]
    });



    const export_sechub_finding_policy_doc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "IAMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:CreateServiceLinkedRole",
            "iam:PassRole"
          ],
          resources: [
            Fn.join('', ["arn:", this.partition ,":iam::", this.account,':role/*']),
          ]   
        }),
        new iam.PolicyStatement({
          sid: "STSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "sts:AssumeRole",
            "sts:GetCallerIdentity"
          ],
          resources: [
            '*'
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SecurityHubAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:BatchUpdateFindings",
            "securityhub:GetFindings"
          ],
          resources: [
            '*'
          ]   
        }),
        new iam.PolicyStatement({
          sid: "S3Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:GetObject",
            "s3:PutObject"
          ],
          resources: [
            security_hub_export_bucket.bucketArn,
            security_hub_export_bucket.arnForObjects("*")
          ]   
        }),
        new iam.PolicyStatement({
          sid: "KMSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Decrypt",
            "kms:Describe*",
            "kms:Encrypt",
            "kms:GenerateDataKey"
          ],
          resources: [
            s3_kms_key.keyArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "InvokeLambdaAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "lambda:InvokeFunction"
          ],
          resources: [
            sh_csv_exporter_function.functionArn,
            sh_csv_updater_function.functionArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SSMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:GetParameters",
            "ssm:PutParameter"
          ],
          resources: [
            Fn.join('', ["arn:", this.partition, ':ssm:', this.region, ':', this.account,':parameter/csvManager/*']),
          ]   
        }),
        new iam.PolicyStatement({
          sid: "StepFunctionsAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "states:SendTaskSuccess",
            "states:SendTaskFailure",
            "states:StartExecution",
            "states:DescribeExecution",
            "states:StopExecution"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "CloudWatchMetricsLambdaAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "cloudwatch:PutMetricData"
          ],
          resources: ["*"],
          conditions: {
            StringEquals: {
              "cloudwatch:namespace": [
                "SecurityHub/CSVExport",
                "AWS/Lambda"
              ]
            }
          }
        }),
      ],
    });

    new iam.ManagedPolicy(this, 'sechub_csv_managed_policy', {
      description: '',
      document:export_sechub_finding_policy_doc,
      managedPolicyName: 'sechub_csv_manager',
      roles: [secub_csv_manager_role]
    });

    // Step Function State Machine Definition for Security Hub CSV Export
    const exportFindingsTask = new stepfunctionstasks.LambdaInvoke(this, 'ExportFindingsTask', {
      lambdaFunction: sh_csv_exporter_function,
      integrationPattern: stepfunctions.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      payload: stepfunctions.TaskInput.fromObject({
        'taskToken': stepfunctions.JsonPath.taskToken,
        'filters': stepfunctions.JsonPath.stringAt('$.filters'),
        'region': stepfunctions.JsonPath.stringAt('$.region'),
        'bucket': stepfunctions.JsonPath.stringAt('$.bucket'),
        'nextToken': stepfunctions.JsonPath.stringAt('$.nextToken'),
        'event': stepfunctions.JsonPath.stringAt('$.event')
      }),
      resultPath: '$.taskResult',
      taskTimeout: stepfunctions.Timeout.duration(Duration.minutes(15)),
      retryOnServiceExceptions: true
    });

    // Add retry configuration for resilient execution
    exportFindingsTask.addRetry({
      errors: ['States.TaskFailed', 'States.Timeout'],
      interval: Duration.seconds(30),
      maxAttempts: 3,
      backoffRate: 2.0
    });

    // Add catch block for error handling
    const exportFailedState = new stepfunctions.Pass(this, 'ExportFailed', {
      result: stepfunctions.Result.fromObject({
        status: 'FAILED',
        message: 'Export failed due to unrecoverable error'
      }),
      resultPath: '$.result'
    });

    exportFindingsTask.addCatch(exportFailedState, {
      errors: ['States.ALL'],
      resultPath: '$.error'
    });

    // Choice state to check if continuation is needed
    const checkContinuationChoice = new stepfunctions.Choice(this, 'CheckContinuation', {
      comment: 'Check if more data needs to be processed'
    });

    // Success state for completed export
    const exportCompleteState = new stepfunctions.Pass(this, 'ExportComplete', {
      result: stepfunctions.Result.fromObject({
        status: 'SUCCESS',
        message: 'Export completed successfully'
      }),
      resultPath: '$.result'
    });

    // Define the state machine flow
    const definition = exportFindingsTask
      .next(checkContinuationChoice
        .when(stepfunctions.Condition.booleanEquals('$.taskResult.hasMore', true), 
          // Update state for next iteration and loop back
          new stepfunctions.Pass(this, 'UpdateStateForContinuation', {
            parameters: {
              'filters.$': '$.filters',
              'region.$': '$.region', 
              'bucket.$': '$.bucket',
              'nextToken.$': '$.taskResult.nextToken',
              'event.$': '$.event'
            }
          }).next(exportFindingsTask)
        )
        .otherwise(exportCompleteState)
      );

    // Create CloudWatch Log Group for Step Function with enhanced configuration
    const stepFunctionLogGroup = new logs.LogGroup(this, 'StateMachineLogGroup', {
      logGroupName: `/aws/stepfunctions/${this.stackName}-SecurityHubExport`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY
    });

    // Create CloudWatch Log Group for Lambda function metrics
    const lambdaMetricsLogGroup = new logs.LogGroup(this, 'LambdaMetricsLogGroup', {
      logGroupName: `/aws/lambda/${this.stackName}_${this.account}_sh_csv_exporter/metrics`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY
    });

    // Create the Step Function state machine with comprehensive logging
    const securityHubExportStateMachine = new stepfunctions.StateMachine(this, 'SecurityHubExportStateMachine', {
      definitionBody: stepfunctions.DefinitionBody.fromChainable(definition),
      role: stepFunctionRole,
      stateMachineName: `${this.stackName}-SecurityHubExport`,
      timeout: Duration.hours(2),
      logs: {
        destination: stepFunctionLogGroup,
        level: stepfunctions.LogLevel.ALL,
        includeExecutionData: true
      },
      tracingEnabled: true
    });

    // Grant EventBridge permission to execute the Step Function
    securityHubExportStateMachine.grantStartExecution(new iam.ServicePrincipal('events.amazonaws.com'));

    // Create SNS topic for monitoring alerts
    const monitoringTopic = new sns.Topic(this, 'SecurityHubExportMonitoringTopic', {
      topicName: `${this.stackName}-SecurityHubExport-Monitoring`,
      displayName: 'Security Hub CSV Export Monitoring Alerts'
    });

    // CloudWatch Alarms for Step Function monitoring
    
    // Step Function execution failure alarm
    const stepFunctionFailureAlarm = new cloudwatch.Alarm(this, 'StepFunctionFailureAlarm', {
      alarmName: `${this.stackName}-StepFunction-ExecutionsFailed`,
      alarmDescription: 'Alarm when Step Function executions fail',
      metric: securityHubExportStateMachine.metricFailed({
        period: Duration.minutes(5),
        statistic: cloudwatch.Statistic.SUM
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    stepFunctionFailureAlarm.addAlarmAction(new cloudwatchActions.SnsAction(monitoringTopic));

    // Step Function execution duration alarm (for long-running executions)
    const stepFunctionDurationMetric = new cloudwatch.Metric({
      namespace: 'AWS/States',
      metricName: 'ExecutionTime',
      dimensionsMap: {
        'StateMachineArn': securityHubExportStateMachine.stateMachineArn
      },
      statistic: cloudwatch.Statistic.MAXIMUM,
      period: Duration.minutes(5)
    });

    const stepFunctionDurationAlarm = new cloudwatch.Alarm(this, 'StepFunctionDurationAlarm', {
      alarmName: `${this.stackName}-StepFunction-LongExecution`,
      alarmDescription: 'Alarm when Step Function executions take too long',
      metric: stepFunctionDurationMetric,
      threshold: Duration.hours(1.5).toMilliseconds(), // Alert if execution takes more than 1.5 hours
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    stepFunctionDurationAlarm.addAlarmAction(new cloudwatchActions.SnsAction(monitoringTopic));

    // Lambda function error rate alarm
    const lambdaErrorAlarm = new cloudwatch.Alarm(this, 'LambdaErrorAlarm', {
      alarmName: `${this.stackName}-Lambda-ErrorRate`,
      alarmDescription: 'Alarm when Lambda function error rate is high',
      metric: sh_csv_exporter_function.metricErrors({
        period: Duration.minutes(5),
        statistic: cloudwatch.Statistic.SUM
      }),
      threshold: 3,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    lambdaErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(monitoringTopic));

    // Lambda function duration alarm
    const lambdaDurationAlarm = new cloudwatch.Alarm(this, 'LambdaDurationAlarm', {
      alarmName: `${this.stackName}-Lambda-Duration`,
      alarmDescription: 'Alarm when Lambda function duration is high',
      metric: sh_csv_exporter_function.metricDuration({
        period: Duration.minutes(5),
        statistic: cloudwatch.Statistic.AVERAGE
      }),
      threshold: Duration.seconds(600).toMilliseconds(), // Alert if average duration > 10 minutes
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    lambdaDurationAlarm.addAlarmAction(new cloudwatchActions.SnsAction(monitoringTopic));

    // Custom metrics for pagination progress monitoring
    const paginationProgressMetric = new cloudwatch.Metric({
      namespace: 'SecurityHub/CSVExport',
      metricName: 'PaginationProgress',
      dimensionsMap: {
        'StateMachine': securityHubExportStateMachine.stateMachineName,
        'Function': sh_csv_exporter_function.functionName
      },
      statistic: cloudwatch.Statistic.MAXIMUM,
      period: Duration.minutes(5)
    });

    // Custom metrics for processing rate monitoring
    const processingRateMetric = new cloudwatch.Metric({
      namespace: 'SecurityHub/CSVExport',
      metricName: 'FindingsProcessedPerMinute',
      dimensionsMap: {
        'StateMachine': securityHubExportStateMachine.stateMachineName,
        'Function': sh_csv_exporter_function.functionName
      },
      statistic: cloudwatch.Statistic.AVERAGE,
      period: Duration.minutes(5)
    });

    // Custom metrics for batch processing monitoring
    const batchSizeMetric = new cloudwatch.Metric({
      namespace: 'SecurityHub/CSVExport',
      metricName: 'BatchSize',
      dimensionsMap: {
        'StateMachine': securityHubExportStateMachine.stateMachineName,
        'Function': sh_csv_exporter_function.functionName
      },
      statistic: cloudwatch.Statistic.AVERAGE,
      period: Duration.minutes(5)
    });

    // Alarm for low processing rate (indicates potential issues)
    const lowProcessingRateAlarm = new cloudwatch.Alarm(this, 'LowProcessingRateAlarm', {
      alarmName: `${this.stackName}-LowProcessingRate`,
      alarmDescription: 'Alarm when findings processing rate is unusually low',
      metric: processingRateMetric,
      threshold: 10, // Alert if processing less than 10 findings per minute
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });
    lowProcessingRateAlarm.addAlarmAction(new cloudwatchActions.SnsAction(monitoringTopic));

    // CloudWatch Dashboard for comprehensive monitoring
    const monitoringDashboard = new cloudwatch.Dashboard(this, 'SecurityHubExportDashboard', {
      dashboardName: `${this.stackName}-SecurityHubExport-Monitoring`,
      widgets: [
        [
          // Step Function execution metrics
          new cloudwatch.GraphWidget({
            title: 'Step Function Executions',
            left: [
              securityHubExportStateMachine.metricStarted({
                label: 'Started',
                color: cloudwatch.Color.BLUE
              }),
              securityHubExportStateMachine.metricSucceeded({
                label: 'Succeeded',
                color: cloudwatch.Color.GREEN
              }),
              securityHubExportStateMachine.metricFailed({
                label: 'Failed',
                color: cloudwatch.Color.RED
              })
            ],
            period: Duration.minutes(5),
            width: 12,
            height: 6
          })
        ],
        [
          // Step Function duration metrics
          new cloudwatch.GraphWidget({
            title: 'Step Function Duration',
            left: [
              stepFunctionDurationMetric.with({
                label: 'Duration',
                color: cloudwatch.Color.PURPLE
              })
            ],
            period: Duration.minutes(5),
            width: 12,
            height: 6
          })
        ],
        [
          // Lambda function metrics
          new cloudwatch.GraphWidget({
            title: 'Lambda Function Performance',
            left: [
              sh_csv_exporter_function.metricInvocations({
                label: 'Invocations',
                color: cloudwatch.Color.BLUE
              }),
              sh_csv_exporter_function.metricErrors({
                label: 'Errors',
                color: cloudwatch.Color.RED
              })
            ],
            right: [
              sh_csv_exporter_function.metricDuration({
                label: 'Duration',
                statistic: cloudwatch.Statistic.AVERAGE,
                color: cloudwatch.Color.ORANGE
              })
            ],
            period: Duration.minutes(5),
            width: 12,
            height: 6
          })
        ],
        [
          // Custom pagination and processing metrics
          new cloudwatch.GraphWidget({
            title: 'Pagination Progress & Processing Rate',
            left: [
              paginationProgressMetric.with({
                label: 'Pagination Progress (%)',
                color: cloudwatch.Color.GREEN
              })
            ],
            right: [
              processingRateMetric.with({
                label: 'Findings/Min',
                color: cloudwatch.Color.BLUE
              }),
              batchSizeMetric.with({
                label: 'Batch Size',
                color: cloudwatch.Color.PURPLE
              })
            ],
            period: Duration.minutes(5),
            width: 12,
            height: 6
          })
        ],
        [
          // Monitoring summary widget
          new cloudwatch.TextWidget({
            markdown: `
## Security Hub CSV Export Monitoring

### Log Groups for Manual Analysis:
- **Step Function Logs**: \`${stepFunctionLogGroup.logGroupName}\`
- **Lambda Function Logs**: \`/aws/lambda/${sh_csv_exporter_function.functionName}\`

### Key Metrics to Monitor:
- Step Function execution success/failure rates
- Lambda function duration and error rates  
- Custom pagination progress metrics
- Processing rate (findings per minute)

### Alarms Configured:
- Step Function execution failures
- Long-running Step Function executions (>1.5 hours)
- High Lambda error rates (>3 errors in 10 minutes)
- High Lambda duration (>10 minutes average)
- Low processing rates (<10 findings/minute)
            `,
            width: 24,
            height: 6
          })
        ]
      ]
    });

    new events.Rule(this, 'Rule', {
      schedule: events.Schedule.expression(Frequency.valueAsString),
      enabled: false,
      description: "Invoke Security Hub findings exporter periodically.",
      targets: [
        new targets.SfnStateMachine(securityHubExportStateMachine, {
          input: events.RuleTargetInput.fromObject({
            "filters": "HighActive",
            "region": PrimaryRegion.valueAsString,
            "bucket": security_hub_export_bucket.bucketName,
            "event": events.EventField.fromPath('$.event')
          })
        })
      ]
    });
    
    // SSM Document for SSM Account configuration with Step Function support
    new ssm.CfnDocument(this, 'create_sh_export_document', {
      documentType: 'Automation',
      name: 'start_sh_finding_export_v2',
      content: {
        "schemaVersion": "0.3",
        "assumeRole": secub_csv_manager_role.roleArn,
        "description": "Generate a Security Hub Findings Export (CSV Manager for Security Hub) outside of the normal export using Step Functions for orchestration.",
        "parameters": {
          "Filters": {
            "type": "String",
            "description": "The canned filter \"HighActive\" or a JSON-formatted string for the GetFindings API filter.",
            "default": 'HighActive'
          },
          "Partition": {
            "type": "String",
            "description": "The partition in which CSV Manager for Security Hub will operate.",
            "default": this.partition
          },
          "Regions": {
            "type": "String",
            "description": "The comma-separated list of regions in which CSV Manager for Security Hub will operate.",
            "default": PrimaryRegion.valueAsString
          },
          "UseStepFunction": {
            "type": "String",
            "description": "Whether to use Step Function orchestration (true) or direct Lambda invocation (false) for backward compatibility.",
            "default": "true",
            "allowedValues": ["true", "false"]
          },
          "Bucket": {
            "type": "String",
            "description": "S3 bucket name for storing exported findings. If not provided, will use default bucket from SSM parameter.",
            "default": security_hub_export_bucket.bucketName
          }
        },
        "mainSteps": [{
          "action": "aws:branch",
          "name": "ChooseExecutionMethod",
          "inputs": {
            "Choices": [
              {
                "Variable": "{{UseStepFunction}}",
                "StringEquals": "true",
                "NextStep": "ExecuteStepFunction"
              }
            ],
            "Default": "ExecuteLambdaDirectly"
          }
        }, {
          "action": "aws:executeStateMachine",
          "name": "ExecuteStepFunction",
          "inputs": {
            "stateMachineArn": securityHubExportStateMachine.stateMachineArn,
            "input": "{ \"filters\" : \"{{Filters}}\" , \"partition\" : \"{{Partition}}\", \"region\" : \"{{Regions}}\", \"bucket\" : \"{{Bucket}}\", \"nextToken\" : \"\", \"event\" : \"ssm\" }"
          },
          "description": "Execute the Step Function for orchestrated Security Hub findings export with pagination support.",
          "outputs": [
            {
              "Name": "stepFunctionExecutionArn",
              "Selector": "$.ExecutionArn",
              "Type": "String"
            },
            {
              "Name": "executionStatus",
              "Selector": "$.Output.status",
              "Type": "String"
            },
            {
              "Name": "outputBucket",
              "Selector": "$.Output.bucket",
              "Type": "String"
            },
            {
              "Name": "outputExportKey",
              "Selector": "$.Output.exportKey",
              "Type": "String"
            }
          ],
          "isEnd": true
        }, {
          "action": "aws:invokeLambdaFunction",
          "name": "ExecuteLambdaDirectly",
          "inputs": {
            "InvocationType": 'RequestResponse',
            "FunctionName": sh_csv_exporter_function.functionName,
            "Payload": "{ \"filters\" : \"{{Filters}}\" , \"partition\" : \"{{Partition}}\", \"regions\" : \"[ {{Regions}} ]\"}"
          },
          'description':'Invoke the CSV Manager for Security Hub lambda function directly (backward compatibility mode).',
          'outputs':[
            {
              'Name': 'resultCode',
              'Selector': '$.Payload.resultCode',
              'Type': 'Integer'
            },
            {
              'Name': 'bucket',
              'Selector': '$.Payload.bucket',
              'Type': 'String'
            },
            {
              'Name': 'exportKey',
              'Selector': '$.Payload.exportKey',
              'Type': 'String'
            }
          ],
          'isEnd': true
        }]
      } 
    });

    // SSM Document for Step Function-based Security Hub export
    new ssm.CfnDocument(this, 'stepfunction_sh_export_document', {
      documentType: 'Automation',
      name: 'start_sh_finding_export_stepfunction_v2',
      content: {
        "schemaVersion": "0.3",
        "assumeRole": secub_csv_manager_role.roleArn,
        "description": "Generate a Security Hub Findings Export using Step Functions orchestration for large dataset processing with pagination support.",
        "parameters": {
          "Filters": {
            "type": "String",
            "description": "The canned filter \"HighActive\" or a JSON-formatted string for the GetFindings API filter.",
            "default": 'HighActive'
          },
          "Partition": {
            "type": "String",
            "description": "The partition in which CSV Manager for Security Hub will operate.",
            "default": this.partition
          },
          "Regions": {
            "type": "String",
            "description": "The comma-separated list of regions in which CSV Manager for Security Hub will operate.",
            "default": PrimaryRegion.valueAsString
          },
          "Bucket": {
            "type": "String",
            "description": "S3 bucket name for storing exported findings. If not provided, will use default bucket from SSM parameter.",
            "default": security_hub_export_bucket.bucketName
          },
          "WaitForCompletion": {
            "type": "String",
            "description": "Whether to wait for Step Function execution to complete (true) or return immediately (false).",
            "default": "true",
            "allowedValues": ["true", "false"]
          }
        },
        "mainSteps": [{
          "action": "aws:executeStateMachine",
          "name": "ExecuteSecurityHubExportStepFunction",
          "inputs": {
            "stateMachineArn": securityHubExportStateMachine.stateMachineArn,
            "input": "{ \"filters\" : \"{{Filters}}\" , \"partition\" : \"{{Partition}}\", \"region\" : \"{{Regions}}\", \"bucket\" : \"{{Bucket}}\", \"nextToken\" : \"\", \"event\" : \"ssm\" }",
            "name": "SSM-SecurityHubExport-{{automation:EXECUTION_ID}}"
          },
          "description": "Execute the Step Function for orchestrated Security Hub findings export with pagination and error handling.",
          "outputs": [
            {
              "Name": "stepFunctionExecutionArn",
              "Selector": "$.ExecutionArn",
              "Type": "String"
            },
            {
              "Name": "stepFunctionStartDate",
              "Selector": "$.StartDate",
              "Type": "String"
            }
          ],
          "nextStep": "CheckWaitForCompletion"
        }, {
          "action": "aws:branch",
          "name": "CheckWaitForCompletion",
          "inputs": {
            "Choices": [
              {
                "Variable": "{{WaitForCompletion}}",
                "StringEquals": "true",
                "NextStep": "WaitForStepFunctionCompletion"
              }
            ],
            "Default": "ReturnExecutionInfo"
          }
        }, {
          "action": "aws:waitForAwsResourceProperty",
          "name": "WaitForStepFunctionCompletion",
          "inputs": {
            "Service": "stepfunctions",
            "Api": "DescribeExecution",
            "ExecutionArn": "{{ExecuteSecurityHubExportStepFunction.executionArn}}",
            "PropertySelector": "$.status",
            "DesiredValues": ["SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"]
          },
          "description": "Wait for Step Function execution to complete.",
          "timeoutSeconds": 7200,
          "nextStep": "GetFinalExecutionStatus"
        }, {
          "action": "aws:executeAwsApi",
          "name": "GetFinalExecutionStatus",
          "inputs": {
            "Service": "stepfunctions",
            "Api": "DescribeExecution",
            "ExecutionArn": "{{ExecuteSecurityHubExportStepFunction.executionArn}}"
          },
          "description": "Get final execution status and output.",
          "outputs": [
            {
              "Name": "status",
              "Selector": "$.status",
              "Type": "String"
            },
            {
              "Name": "output",
              "Selector": "$.output",
              "Type": "String"
            },
            {
              "Name": "stopDate",
              "Selector": "$.stopDate",
              "Type": "String"
            }
          ],
          "isEnd": true
        }, {
          "action": "aws:executeAwsApi",
          "name": "ReturnExecutionInfo",
          "inputs": {
            "Service": "stepfunctions",
            "Api": "DescribeExecution",
            "ExecutionArn": "{{ExecuteSecurityHubExportStepFunction.executionArn}}"
          },
          "description": "Return execution information without waiting for completion.",
          "outputs": [
            {
              "Name": "status",
              "Selector": "$.status",
              "Type": "String"
            },
            {
              "Name": "executionArn",
              "Selector": "$.executionArn",
              "Type": "String"
            }
          ],
          "isEnd": true
        }]
      } 
    });
    
    // SSM Document for SSM Account configuration
    new ssm.CfnDocument(this, 'update_sh_export_document', {
      documentType: 'Automation',
      name: 'start_sechub_csv_update',
      content: {
        "schemaVersion": "0.3",
        "assumeRole": secub_csv_manager_role.roleArn,
        "description": "Update a Security Hub Findings Update (CSV Manager for Security Hub) outside of the normal Update.",
        "parameters": {
          "Source": {
            "type": "String",
            "description": "An S3 URI containing the CSV file to update. i.e. s3://<bucket_name>/Findings/SecurityHub-20220415-115112.csv",
            "default": ''
          },
          "PrimaryRegion": {
            "type": "String",
            "description": "Region to pull the CSV file from.",
            "default": PrimaryRegion
          }
        },
        "mainSteps": [{
          "action": "aws:invokeLambdaFunction",
          "name": "InvokeLambdaforSHFindingUpdate",
          "inputs": {
            "InvocationType": 'RequestResponse',
            "FunctionName": sh_csv_updater_function.functionName,
            "Payload": "{ \"input\" : \"{{Source}}\" , \"primaryRegion\" : \"{{PrimaryRegion}}\"}"
          },
          'description':'Invoke the CSV Manager Update for Security Hub lambda function.',
          'outputs':[
            {
              'Name': 'resultCode',
              'Selector': '$.Payload.resultCode',
              'Type': 'Integer'
            }
          ],
          'isEnd':true
        }]
      } 
    });

    //SSM Parameters
    new ssm.StringParameter(this, 'BucketNameParameter', {
      description: 'The S3 bucket where Security Hub are exported.',
      parameterName: '/csvManager/bucket',
      stringValue: security_hub_export_bucket.bucketName,
    });
    
    new ssm.StringParameter(this, 'KMSKeyParameter', {
      description: 'The KMS key encrypting the S3 bucket objects.',
      parameterName: '/csvManager/key',
      stringValue: s3_kms_key.keyArn,
    });

    new ssm.StringParameter(this, 'CodeFolderParameter', {
      description: 'The folder where CSV Manager for Security Hub code is stored.',
      parameterName: '/csvManager/folder/code',
      stringValue: CodeFolder.valueAsString,
    });

    new ssm.StringParameter(this, 'FindingsFolderParameter', {
      description: 'The folder where CSV Manager for Security Hub findings are exported.',
      parameterName: '/csvManager/folder/findings',
      stringValue: FindingsFolder.valueAsString,
    });

    new ssm.StringParameter(this, 'ArchiveKeyParameter', {
      description: 'The name of the ZIP archive containing CSV Manager for Security Hub Lambda code.',
      parameterName: '/csvManager/object/codeArchive',
      stringValue: 'Not Initialized',
    });

    new ssm.StringParameter(this, 'PartitionParameter', {
      description: 'The partition in which CSV Manager for Security Hub will operate.',
      parameterName: '/csvManager/partition',
      stringValue: Partition.valueAsString,
    });

    new ssm.StringParameter(this, 'RegionParameter', {
      description: 'The list of regions in which CSV Manager for Security Hub will operate.',
      parameterName: '/csvManager/regionList',
      stringValue: Regions.valueAsString,
    });

    // SSM Parameters for Step Function state management
    new ssm.StringParameter(this, 'NextTokenParameter', {
      description: 'Pagination token for resuming Security Hub findings export from last position.',
      parameterName: '/csvManager/export/nextToken',
      stringValue: "0",
    });

    new ssm.StringParameter(this, 'CurrentExecutionParameter', {
      description: 'Current Step Function execution ID for tracking active export processes.',
      parameterName: '/csvManager/export/currentExecution',
      stringValue: "0",
    });

    new ssm.StringParameter(this, 'ProcessedCountParameter', {
      description: 'Number of Security Hub findings processed in current export execution.',
      parameterName: '/csvManager/export/processedCount',
      stringValue: '0',
    });

}
}
