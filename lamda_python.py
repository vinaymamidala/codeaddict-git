#For_Lower_env_Only
#Not_for_production_use

import boto3
import os#
from datetime import datetime, timezone

iam = boto3.client('iam')
sns = boto3.client('sns')

def lambda_handler(event, context):
    # Config (use env vars in prod)
    MAX_AGE_DAYS = int(os.environ.get("MAX_AGE_DAYS", "0"))
    SNS_TOPIC_ARN = os.environ.get(
        "SNS_TOPIC_ARN",
        "arn:aws:sns:ap-south-1:496203436083:IAM-Security-Alerts"
    )

    disabled_keys = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            key_paginator = iam.get_paginator("list_access_keys")
            for key_page in key_paginator.paginate(UserName=username):
                for key in key_page["AccessKeyMetadata"]:
                    if key["Status"] != "Active":
                        continue

                    age_days = (
                        datetime.now(timezone.utc) - key["CreateDate"]
                    ).days

                    # >= allows MAX_AGE_DAYS=0 testing
                    if age_days >= MAX_AGE_DAYS:
                        iam.update_access_key(
                            UserName=username,
                            AccessKeyId=key["AccessKeyId"],
                            Status="Inactive"
                        )
                        disabled_keys.append(
                            f"{username} ({key['AccessKeyId']}) - {age_days} days"
                        )

    if disabled_keys:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="IAM Access Key Audit Alert",
            Message="Disabled IAM access keys:\n\n" + "\n".join(disabled_keys)
        )

    return {
        "disabled_count": len(disabled_keys),
        "disabled_keys": disabled_keys
    }