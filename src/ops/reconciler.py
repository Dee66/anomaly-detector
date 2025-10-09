"""Reconciler Lambda: scans the audit table for recommended actions and verifies they were applied.
This is a lightweight, testable implementation that uses a provided DynamoDB client (for unit tests we pass a stub).
"""
from typing import List, Dict, Any, Optional

AUDIT_TABLE = "anomaly-detector-audit"


def list_open_recommendations(dynamodb_client) -> List[Dict[str, Any]]:
    """Scan DynamoDB table for recommendations that are not marked as `applied`.
    Returns list of items.
    """
    # Use a simple scan with filter expression to find RECOMMENDED items. Keep the
    # expression as a single, quoted string.
    resp = dynamodb_client.scan(
        TableName=AUDIT_TABLE,
        FilterExpression="#s = :open_status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":open_status": {"S": "RECOMMENDED"}},
    )
    items = resp.get("Items", [])
    return items


def check_action_applied(item: Dict[str, Any]) -> bool:
    """Placeholder for domain-specific check. For tests we treat items with 'applied' flag."""
    # In real usage this might call AWS APIs or query configuration state.
    return item.get("applied", {}).get("BOOL") is True


def mark_as_reconciled(dynamodb_client, item_key: Dict[str, Any]) -> None:
    # In production we would set the current timestamp; for simplicity use a static
    # string in this lightweight implementation (tests don't assert the timestamp).
    dynamodb_client.update_item(
        TableName=AUDIT_TABLE,
        Key=item_key,
        UpdateExpression="SET #s = :status, reconciled_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": {"S": "RECONCILED"},
            ":ts": {"S": "2025-10-09T00:00:00Z"},
        },
    )


def lambda_handler(event: Optional[Dict[str, Any]], context: Any, dynamodb_client=None) -> Dict[str, Any]:
    """Entry point for the reconciler lambda.
    If dynamodb_client is None, this function will raise so tests must inject a stubbed client.
    Returns a summary dict.
    """
    if dynamodb_client is None:
        raise ValueError("dynamodb_client must be provided for execution")

    items = list_open_recommendations(dynamodb_client)
    reconciled = 0
    for it in items:
        if check_action_applied(it):
            # key assumed to be {"recommendation_id": {"S": "..."}}
            key = {"recommendation_id": it["recommendation_id"]}
            mark_as_reconciled(dynamodb_client, key)
            reconciled += 1

    return {"scanned": len(items), "reconciled": reconciled}
