import pytest

from src.ops import reconciler


class DummyDDB:
    def __init__(self, items):
        self._items = items
        self.updated = []

    def scan(self, TableName, FilterExpression, ExpressionAttributeNames, ExpressionAttributeValues):
        return {"Items": self._items}

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues):
        self.updated.append(Key)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def make_item(rec_id: str, applied: bool):
    return {
        "recommendation_id": {"S": rec_id},
        "applied": {"BOOL": applied},
        "status": {"S": "RECOMMENDED"},
    }


def test_reconciler_marks_applied_items():
    items = [make_item("r1", True), make_item("r2", False)]
    ddb = DummyDDB(items)

    result = reconciler.lambda_handler(None, None, dynamodb_client=ddb)

    assert result["scanned"] == 2
    assert result["reconciled"] == 1
    assert ddb.updated == [{"recommendation_id": {"S": "r1"}}]
