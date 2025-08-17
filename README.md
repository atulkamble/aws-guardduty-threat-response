here’s a complete, production-style mini-project to **detect & auto-respond to GuardDuty threats** using **EventBridge → SNS + Lambda**. It’s built for quick deploy via Terraform and includes a Python Lambda that can **quarantine or stop EC2 instances** and **disable compromised IAM users**.

# 🧩 What you’ll build

* **GuardDuty** enabled with malware-scan & EKS data sources (where supported).
* **EventBridge rule** that listens for GuardDuty findings (filterable by severity/type).
* **SNS topic** for email alerts.
* **Lambda (Python 3.12)** auto-remediator to:

  * Quarantine EC2 instance (replace SG with a “quarantine” SG).
  * Stop suspicious EC2 instance (e.g., crypto miner).
  * Disable IAM user (deactivate keys + remove console login).
* One-click **sample findings** generation to test end-to-end.

---

## 📁 Repo structure

```
guardduty-threat-response/
├─ terraform/
│  ├─ main.tf
│  ├─ variables.tf
│  ├─ outputs.tf
│  ├─ guardduty.tf
│  ├─ eventbridge.tf
│  ├─ iam.tf
│  ├─ sns.tf
│  └─ lambda.tf
├─ lambda/
│  ├─ auto_remediate.py
│  └─ requirements.txt   # (empty, boto3 is in AWS runtime)
└─ README.md
```

---

## ⚙️ Terraform — provider & locals (`terraform/main.tf`)

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  project          = "guardduty-threat-response"
  quarantine_sg    = "${local.project}-quarantine-sg"
  lambda_name      = "${local.project}-lambda"
  event_rule_name  = "${local.project}-gd-findings"
  sns_topic_name   = "${local.project}-alerts"
  # Default: trigger on severity >= 4.0
  finding_severity_threshold = var.severity_threshold
}
```

---

## 🔐 Variables (`terraform/variables.tf`)

```hcl
variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "alert_email" {
  type        = string
  description = "Email to subscribe to SNS alerts"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where quarantine SG is created"
}

variable "severity_threshold" {
  type        = number
  description = "GuardDuty severity lower bound to trigger automation"
  default     = 4.0
}
```

---

## 📤 Outputs (`terraform/outputs.tf`)

```hcl
output "guardduty_detector_id" { value = aws_guardduty_detector.this.id }
output "sns_topic_arn"         { value = aws_sns_topic.alerts.arn }
output "lambda_function_name"  { value = aws_lambda_function.auto.name }
output "event_rule_name"       { value = aws_cloudwatch_event_rule.gd_findings.name }
output "quarantine_sg_id"      { value = aws_security_group.quarantine.id }
```

---

## 🛡️ GuardDuty enablement (`terraform/guardduty.tf`)

```hcl
resource "aws_guardduty_detector" "this" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes = true
      }
    }
  }
}
```

> This enables GuardDuty with common data sources (features vary by region—safe defaults above).

---

## 📣 SNS for alerts (`terraform/sns.tf`)

```hcl
resource "aws_sns_topic" "alerts" {
  name = local.sns_topic_name
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
```

> You’ll get a **confirmation email**. Click “Confirm subscription” to start receiving alerts.

---

## 🧰 IAM for Lambda (`terraform/iam.tf`)

```hcl
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["lambda.amazonaws.com"] }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${local.project}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Basic logging
resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Permissions for EC2 quarantine/stop + IAM user disable
data "aws_iam_policy_document" "lambda_inline" {
  statement {
    sid     = "Ec2Quarantine"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:StopInstances"
    ]
    resources = ["*"]
  }

  statement {
    sid     = "IamDisableUser"
    actions = [
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
      "iam:DeleteLoginProfile"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "lambda_inline" {
  name   = "${local.project}-lambda-inline"
  policy = data.aws_iam_policy_document.lambda_inline.json
}

resource "aws_iam_role_policy_attachment" "lambda_inline_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_inline.arn
}
```

---

## 🛰️ Quarantine Security Group (`terraform/iam.tf` continued or new file)

```hcl
resource "aws_security_group" "quarantine" {
  name        = local.quarantine_sg
  description = "No ingress/egress — isolates compromised instances"
  vpc_id      = var.vpc_id

  # No ingress
  egress = []  # block all egress (strict quarantine)
}
```

---

## 🧠 Lambda packaging & function (`terraform/lambda.tf`)

```hcl
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/../lambda/build/auto_remediate.zip"
}

resource "aws_lambda_function" "auto" {
  function_name = local.lambda_name
  role          = aws_iam_role.lambda_exec.arn
  handler       = "auto_remediate.lambda_handler"
  runtime       = "python3.12"
  filename      = data.archive_file.lambda_zip.output_path
  timeout       = 60
  memory_size   = 256
  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
    }
  }
}
```

---

## ⏰ EventBridge rule & targets (`terraform/eventbridge.tf`)

```hcl
# Event pattern: GuardDuty findings with severity >= threshold
# Numeric matching requires the "numeric" operator array syntax
locals {
  gd_event_pattern = jsonencode({
    "source"      : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"],
    "detail" : {
      "severity" : [{ "numeric" : [">=", local.finding_severity_threshold] }]
    }
  })
}

resource "aws_cloudwatch_event_rule" "gd_findings" {
  name         = local.event_rule_name
  description  = "Route GuardDuty findings to Lambda & SNS"
  event_pattern = local.gd_event_pattern
}

resource "aws_cloudwatch_event_target" "to_lambda" {
  rule      = aws_cloudwatch_event_rule.gd_findings.name
  target_id = "lambda"
  arn       = aws_lambda_function.auto.arn
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.gd_findings.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.gd_findings.arn
}
```

> Adjust the **event pattern** if you want to target select finding types (examples below).

---

## 🐍 Lambda code (`lambda/auto_remediate.py`)

```python
import json
import os
import boto3
import logging

logging.getLogger().setLevel(logging.INFO)

ec2 = boto3.client("ec2")
iam = boto3.client("iam")

QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID", "")

# ---------- Helpers ----------
def _get_primary_eni_id(instance_id: str):
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = desc.get("Reservations", [])
    for r in reservations:
        for i in r.get("Instances", []):
            enis = sorted(i.get("NetworkInterfaces", []),
                          key=lambda e: 0 if e.get("Attachment", {}).get("DeviceIndex", 0) == 0 else 1)
            if enis:
                return enis[0]["NetworkInterfaceId"]
    return None

def quarantine_instance(instance_id: str):
    if not QUARANTINE_SG_ID:
        logging.warning("No QUARANTINE_SG_ID set; skipping quarantine.")
        return

    eni_id = _get_primary_eni_id(instance_id)
    if not eni_id:
        logging.error(f"Could not find primary ENI for {instance_id}")
        return

    logging.info(f"Applying quarantine SG {QUARANTINE_SG_ID} to ENI {eni_id}")
    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=eni_id,
        Groups=[QUARANTINE_SG_ID]
    )

def stop_instance(instance_id: str):
    logging.info(f"Stopping instance {instance_id}")
    ec2.stop_instances(InstanceIds=[instance_id])

def disable_iam_user(user_name: str):
    logging.info(f"Disabling IAM user {user_name}")
    # Deactivate all access keys
    keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    for k in keys:
        iam.update_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"], Status="Inactive")
    # Remove console login (if exists)
    try:
        iam.delete_login_profile(UserName=user_name)
    except iam.exceptions.NoSuchEntityException:
        pass

# ---------- Router ----------
def handle_finding(detail: dict):
    finding_type = detail.get("type", "")
    severity     = detail.get("severity", 0)
    title        = detail.get("title", "")

    logging.info(f"Finding: type={finding_type}, severity={severity}, title={title}")

    # EC2-related
    inst = detail.get("resource", {}).get("instanceDetails", {})
    instance_id = inst.get("instanceId")

    # IAM-related
    akd = detail.get("resource", {}).get("accessKeyDetails", {})
    user_name = akd.get("userName")

    # Example playbook:
    if finding_type.startswith("UnauthorizedAccess:EC2/SSHBruteForce") and instance_id:
        quarantine_instance(instance_id)

    elif finding_type.startswith("CryptoCurrency:EC2/BitcoinTool") and instance_id:
        stop_instance(instance_id)

    elif finding_type.startswith("UnauthorizedAccess:IAMUser/ConsoleLogin") and user_name:
        disable_iam_user(user_name)

    else:
        # Catch-all: for high severity EC2 findings, quarantine
        if instance_id and float(severity) >= 6.0:
            quarantine_instance(instance_id)

def lambda_handler(event, context):
    logging.info("Event: " + json.dumps(event))
    detail = event.get("detail", {})
    try:
        handle_finding(detail)
        return {"status": "ok"}
    except Exception as e:
        logging.exception("Remediation failed")
        raise
```

> Tweak the **playbook mapping** as you wish. You can add branches for S3 exfiltration, RDP brute force, etc.

---

## 🎯 (Optional) Target by finding type instead of severity

Replace `locals.gd_event_pattern` with a type-focused match:

```hcl
locals {
  gd_event_pattern = jsonencode({
    "source"      : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"],
    "detail" : {
      "type" : [
        {"prefix": "UnauthorizedAccess:EC2/SSHBruteForce"},
        {"prefix": "CryptoCurrency:EC2/BitcoinTool"},
        {"prefix": "UnauthorizedAccess:IAMUser/ConsoleLogin"}
      ]
    }
  })
}
```

You can **combine** the two (type + severity) if needed.

---

## 🚀 Deploy steps

1. **Clone & edit variables**

```bash
git clone <your repo> guardduty-threat-response
cd guardduty-threat-response/terraform

# Create terraform.tfvars
cat > terraform.tfvars <<EOF
aws_region      = "us-east-1"
alert_email     = "you@example.com"
vpc_id          = "vpc-xxxxxxxx"
severity_threshold = 4.0
EOF
```

2. **Init & apply**

```bash
terraform init
terraform validate
terraform apply -auto-approve
```

3. **Confirm SNS email**

* Check your inbox for “AWS Notification – Subscription Confirmation” and confirm.

4. **Generate sample findings** (end-to-end test)

```bash
DETECTOR_ID=$(terraform output -raw guardduty_detector_id)

aws guardduty create-sample-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-types '[
    "UnauthorizedAccess:EC2/SSHBruteForce",
    "CryptoCurrency:EC2/BitcoinTool.B",
    "UnauthorizedAccess:IAMUser/ConsoleLogin"
  ]'
```

5. **Observe**

* You should receive **SNS email alerts**.
* Check **CloudWatch Logs** for your Lambda to see remediation actions.
* Verify remediation:

  * For EC2: instance is **stopped** or its primary ENI is attached only to **quarantine SG**.
  * For IAM: user **login profile removed** and **access keys Inactive**.

---

## 🧪 Manual test helpers

* To test **EC2 quarantine** path quickly, set a higher threshold and use the SSHBruteForce sample; then confirm the instance’s **primary ENI** has only the quarantine SG.
* To revert: reattach original SGs (or simply terminate test instance), and re-create IAM login profile for test user if you removed it.

---

## 🔒 Security & Ops notes (best practices)

* Use a **dedicated remediation account/role** with **least privilege**; scope IAM actions to resource ARNs if you know the exact patterns.
* Create separate EventBridge rules per playbook (easier to reason & audit).
* For real environments, record every action to **Security Hub** or a central **SIEM**.
* Consider adding **dead-letter queue** & **retry policies** to Lambda.
* Extend the Lambda for:

  * S3: auto-block public access on suspicious buckets or apply deny policies.
  * VPC: detach Internet Gateway / NACL lockdown for specific subnets (advanced).
  * EKS: cordon & drain nodes (if findings indicate node compromise).

---

## 📝 README starter (put in `README.md`)

* Project overview
* Architecture diagram (GD → EventBridge → SNS/Lambda)
* Setup, variables, deploy, test, cleanup
* Playbook mapping table (Finding type → Action)
* Rollback instructions

---

## 🧹 Cleanup

```bash
terraform destroy
```

---

If you want, I can also:

* Add **per-finding-type** EventBridge rules,
* Integrate with **Security Hub**, or
* Wire **Slack/MS Teams** notifications via webhook Lambda.
